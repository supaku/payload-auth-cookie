import { beforeAll, afterAll, describe, expect, it } from 'vitest'
import { SignJWT } from 'jose'
import { createAuthEndpoints } from '../endpoints/index.js'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { buildConfig, getPayload, createPayloadRequest } from 'payload'
import type { Payload } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import { authPlugin } from '../plugin.js'
import { generateUserToken } from './session.js'
import { resolveSSOUser, linkAccountIdentity, revokeAccountIdentity } from './identity-resolver.js'

// Opt-in local disposable replica set only. Never reads DATABASE_URI or application .env files.
const suite = process.env.RUN_IDENTITY_ADAPTER_TESTS === '1' ? describe : describe.skip
suite('linked identities against transactional MongoDB', () => {
  let server: MongoMemoryReplSet
  let payload: Payload
  let closedPayload: Payload
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
  const closedConfig = {
    ...config,
    accountsCollectionSlug: `${config.accountsCollectionSlug}-closed`,
    allowSignUp: false,
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
        collections: [
          {
            slug: 'test-users',
            auth: { disableLocalStrategy: true, useSessions: false },
            fields: [],
          },
          { slug: 'local-users', auth: { useSessions: false }, fields: [] },
        ],
        plugins: [authPlugin(config)],
      }),
    })
    await payload.db.connection.syncIndexes()
    closedPayload = await getPayload({
      key: 'closed-lifecycle',
      config: await buildConfig({
        secret: 'isolated-closed-test-secret',
        db: mongooseAdapter({ url: server.getUri('closed-lifecycle') }),
        admin: { disable: true },
        collections: [
          {
            slug: 'test-users',
            auth: { disableLocalStrategy: true, useSessions: false },
            fields: [],
          },
        ],
        plugins: [authPlugin(closedConfig)],
      }),
    })
    await closedPayload.db.connection.syncIndexes()
  }, 180_000)
  afterAll(async () => {
    if (payload) {
      await payload.destroy()
    }
    if (closedPayload) {
      await closedPayload.destroy()
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

  it('rejects local JWT fallback into a linked collection while retaining unrelated local JWT authentication', async () => {
    const linked = await resolveSSOUser({
      payload,
      config,
      session: { email: 'fallback@example.test', userId: 'fallback-subject', emailVerified: true },
    })
    const linkedToken = await generateUserToken(payload, 'test-users', linked.id)
    await revokeAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: 'fallback-subject' },
      linkedBy: 'revoke:fallback',
    })
    const rejected = await payload.auth({
      headers: new Headers({ authorization: `JWT ${linkedToken.token}` }),
    })
    expect(rejected.user).toBeNull()
    const local = await payload.create({
      collection: 'local-users' as never,
      data: { email: 'local@example.test', password: 'isolated-test-password' },
      overrideAccess: true,
    })
    const localToken = await generateUserToken(payload, 'local-users', local.id)
    const accepted = await payload.auth({
      headers: new Headers({ authorization: `JWT ${localToken.token}` }),
    })
    expect(accepted.user?.id).toBe(local.id)
    expect(accepted.user?.collection).toBe('local-users')
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

  it('session inspection enforces subject ownership, revocation, and non-provisioning with the real adapter', async () => {
    const owner = await resolveSSOUser({
      payload,
      config,
      session: {
        email: 'test-session-owner@example.test',
        userId: 'test-session-owner',
        emailVerified: true,
      },
    })
    const victim = await payload.create({
      collection: config.usersCollectionSlug as never,
      data: { email: 'test-session-victim@example.test', firstName: 'Victim' },
      overrideAccess: true,
    })
    const endpoint = createAuthEndpoints(config).find(
      (entry) => entry.path === '/test/auth/session',
    )!
    const inspect = async (claims: Record<string, unknown>) => {
      const token = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'HS256' })
        .sign(new TextEncoder().encode('test'))
      const response = await endpoint.handler({
        payload,
        headers: new Headers({ cookie: `sso=${token}` }),
      } as never)
      return (await response.json()) as { authenticated: boolean; user?: { id: string | number } }
    }
    const claims = {
      email: victim.email,
      userId: 'test-session-owner',
      emailVerified: true,
      firstName: 'Injected',
    }
    expect((await inspect(claims)).user?.id).toBe(owner.id)
    await revokeAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: 'test-session-owner' },
      linkedBy: 'revoke:session',
    })
    expect(await inspect(claims)).toEqual({ authenticated: false })
    expect(await inspect({ ...claims, userId: 'unbound-subject' })).toEqual({
      authenticated: false,
    })
    expect(await inspect({ email: victim.email })).toEqual({ authenticated: false })
    const unchanged = await payload.findByID({
      collection: config.usersCollectionSlug as never,
      id: victim.id,
      overrideAccess: true,
    })
    expect(unchanged.firstName).toBe('Victim')
  })

  it('full Payload request lifecycle preserves permitted signup and closed-mode verified bootstrap without email takeover', async () => {
    const inspect = async (
      fixturePayload: Payload,
      claims: Record<string, unknown>,
      isClosed: boolean,
    ) => {
      const token = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'HS256' })
        .sign(new TextEncoder().encode('test'))
      const req = await createPayloadRequest({
        config: fixturePayload.config,
        ...(isClosed ? { payloadInstanceCacheKey: 'closed-lifecycle' } : {}),
        request: new Request('http://127.0.0.1/api/test/auth/session', {
          headers: { cookie: `sso=${token}` },
        }),
      })
      expect(req.payload).toBe(fixturePayload)
      const endpoint = createAuthEndpoints(isClosed ? closedConfig : config).find(
        (entry) => entry.path === '/test/auth/session',
      )!
      const response = await endpoint.handler(req)
      return (await response.json()) as { authenticated: boolean; user?: { id: string | number } }
    }
    const closedClaims = {
      email: 'closed-new@example.test',
      userId: 'closed-central',
      emailVerified: true,
    }
    expect(await inspect(closedPayload, closedClaims, true)).toEqual({ authenticated: false })
    expect(
      (
        await closedPayload.find({
          collection: config.usersCollectionSlug as never,
          overrideAccess: true,
        })
      ).docs,
    ).toHaveLength(0)
    const legacy = await closedPayload.create({
      collection: config.usersCollectionSlug as never,
      data: { email: 'closed-legacy@example.test' },
      overrideAccess: true,
    })
    const bootstrap = { ...closedClaims, email: legacy.email }
    expect(await inspect(closedPayload, { ...bootstrap, emailVerified: false }, true)).toEqual({
      authenticated: false,
    })
    expect(
      (
        await closedPayload.find({
          collection: closedConfig.accountsCollectionSlug as never,
          overrideAccess: true,
        })
      ).docs,
    ).toHaveLength(0)
    expect((await inspect(closedPayload, bootstrap, true)).user?.id).toBe(legacy.id)
    expect(
      (
        await closedPayload.find({
          collection: config.usersCollectionSlug as never,
          overrideAccess: true,
        })
      ).docs,
    ).toHaveLength(1)
    expect(
      (await inspect(closedPayload, { ...bootstrap, email: 'changed@example.test' }, true)).user
        ?.id,
    ).toBe(legacy.id)
    expect(
      await inspect(closedPayload, { ...bootstrap, userId: 'collision-subject' }, true),
    ).toEqual({ authenticated: false })
    await revokeAccountIdentity({
      payload: closedPayload,
      config: closedConfig,
      identity: { provider: 'central', subject: bootstrap.userId },
      linkedBy: 'revoke:lifecycle',
    })
    expect(await inspect(closedPayload, bootstrap, true)).toEqual({ authenticated: false })
    expect(
      (
        await closedPayload.find({
          collection: config.usersCollectionSlug as never,
          overrideAccess: true,
        })
      ).docs,
    ).toHaveLength(1)
    expect(
      (
        await closedPayload.find({
          collection: closedConfig.accountsCollectionSlug as never,
          overrideAccess: true,
        })
      ).docs,
    ).toHaveLength(1)
    const signup = await inspect(
      payload,
      {
        email: 'test-lifecycle-signup@example.test',
        userId: 'test-lifecycle-signup',
        emailVerified: true,
      },
      false,
    )
    expect(signup.authenticated).toBe(true)
    expect(signup.user?.id).toBeDefined()
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
