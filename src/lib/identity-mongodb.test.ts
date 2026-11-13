import { beforeAll, afterAll, describe, expect, it } from 'vitest'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { buildConfig, getPayload } from 'payload'
import type { Payload } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import { authPlugin } from '../plugin.js'
import { resolveSSOUser, linkAccountIdentity, revokeAccountIdentity } from './identity-resolver.js'

// Opt-in local disposable replica set only. Never reads DATABASE_URI or application .env files.
const suite = process.env.RUN_IDENTITY_ADAPTER_TESTS === '1' ? describe : describe.skip
suite('linked identities against transactional MongoDB', () => {
  let server: MongoMemoryReplSet
  let payload: Payload
  const config: AuthPluginConfig = {
    name: 'test',
    usersCollectionSlug: 'test-users',
    accountsCollectionSlug: 'test-accounts',
    identity: { provider: 'central', subjectField: 'userId', allowVerifiedEmailBootstrap: true },
    allowSignUp: true,
    sso: {
      cookieName: 'sso',
      loginUrl: 'https://example.test/login',
      logoutUrl: 'https://example.test/logout',
      jwt: { secret: 'test' },
    },
  }
  beforeAll(async () => {
    server = await MongoMemoryReplSet.create({
      replSet: { count: 1 },
      binary: { version: '7.0.24' },
    })
    payload = await getPayload({
      config: await buildConfig({
        secret: 'isolated-test-secret-not-an-application-secret',
        db: mongooseAdapter({ url: server.getUri('linked-identities-test') }),
        admin: { disable: true },
        collections: [{ slug: 'test-users', auth: { disableLocalStrategy: true }, fields: [] }],
        plugins: [authPlugin(config)],
      }),
    })
    await payload.db.connection.syncIndexes()
  }, 180_000)
  afterAll(async () => {
    if (payload) {
      await payload.destroy()
    }
    if (server) {
      await server.stop()
    }
  })

  it('creates a user and account inside one real adapter transaction and permits explicit second identity', async () => {
    const session = { email: 'mongo@example.test', userId: 'central-mongo', emailVerified: true }
    const user = await resolveSSOUser({ payload, config, session })
    expect(user._ssoIdentity).toEqual({
      realm: 'test',
      provider: 'central',
      subject: 'central-mongo',
    })
    await linkAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: 'mongo-second' },
      userID: user.id,
      linkedBy: 'test-command',
    })
    await linkAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: 'mongo-third' },
      userID: user.id,
      linkedBy: 'test-command-2',
    })
    const again = await resolveSSOUser({
      payload,
      config,
      session: { ...session, userId: 'mongo-second', email: 'changed@example.test' },
    })
    expect(again.id).toBe(user.id)
    const accounts = await payload.find({
      collection: 'test-accounts' as never,
      overrideAccess: true,
    })
    expect(accounts.docs).toHaveLength(3)
    await revokeAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: 'central-mongo' },
      linkedBy: 'revoke-command',
    })
    await expect(resolveSSOUser({ payload, config, session })).rejects.toThrow('revoked')
  })

  it('denies forged local account updates even with overrideAccess true', async () => {
    const accounts = await payload.find({
      collection: 'test-accounts' as never,
      overrideAccess: true,
    })
    await expect(
      payload.update({
        collection: 'test-accounts' as never,
        id: accounts.docs[0].id,
        data: { subject: 'forged' },
        overrideAccess: true,
        context: { ssoAccountCapability: {} },
      }),
    ).rejects.toThrow('server-side')
  })

  it('arbitrates concurrent identical and different-subject legacy claims', async () => {
    const same = { email: 'mongo-race@example.test', userId: 'race-subject', emailVerified: true }
    const results = await Promise.all(
      Array.from({ length: 3 }, () => resolveSSOUser({ payload, config, session: same })),
    )
    expect(new Set(results.map((user) => user.id)).size).toBe(1)
    await payload.create({
      collection: 'test-users' as never,
      data: { email: 'legacy-race@example.test' },
      overrideAccess: true,
    })
    const competing = await Promise.allSettled(
      ['one', 'two'].map((userId) =>
        resolveSSOUser({
          payload,
          config,
          session: { email: 'legacy-race@example.test', emailVerified: true, userId },
        }),
      ),
    )
    expect(competing.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
  })
})
