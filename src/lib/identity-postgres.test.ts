import { beforeAll, afterAll, describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:net'
import { createRequire } from 'node:module'
import { buildConfig, getPayload } from 'payload'
import type { Payload, DatabaseAdapterObj } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import { authPlugin } from '../plugin.js'
import { withAccountsCollection } from '../collection/withAccountsCollection.js'
import { resolveSSOUser, linkAccountIdentity, revokeAccountIdentity } from './identity-resolver.js'

// Creates and stops its own temporary cluster on a free loopback port. Never uses DATABASE_URI.
const suite = process.env.RUN_IDENTITY_POSTGRES_TESTS === '1' ? describe : describe.skip
suite('linked identities against disposable Postgres', () => {
  let directory: string
  let payload: Payload
  let isStarted = false
  const binary = process.env.PG_TEST_BIN || '/opt/homebrew/opt/postgresql@17/bin'
  const config: AuthPluginConfig = {
    name: 'pg',
    usersCollectionSlug: 'pg-users',
    accountsCollectionSlug: 'pg-accounts',
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
    const require = createRequire(new URL('../../dev/package.json', import.meta.url))
    const modulePath = require.resolve('@payloadcms/db-postgres')
    const { postgresAdapter } = (await import(modulePath)) as {
      postgresAdapter: (args: { pool: { connectionString: string } }) => DatabaseAdapterObj
    }
    directory = mkdtempSync(join(tmpdir(), 'payload-auth-cookie-pg-'))
    const port = await new Promise<number>((resolve, reject) => {
      const socket = createServer()
      socket.on('error', reject)
      socket.listen(0, '127.0.0.1', () => {
        const address = socket.address()
        if (!address || typeof address === 'string') {
          return reject(new Error('No test port'))
        }
        socket.close(() => resolve(address.port))
      })
    })
    execFileSync(
      join(binary, 'initdb'),
      ['-D', join(directory, 'data'), '-U', 'identity_test', '-A', 'trust', '--no-locale'],
      { stdio: 'pipe' },
    )
    execFileSync(
      join(binary, 'pg_ctl'),
      [
        '-D',
        join(directory, 'data'),
        '-l',
        join(directory, 'postgres.log'),
        '-o',
        `-h 127.0.0.1 -p ${port} -k ${directory}`,
        '-w',
        'start',
      ],
      { stdio: 'pipe' },
    )
    isStarted = true
    payload = await getPayload({
      config: await buildConfig({
        secret: 'isolated-postgres-test-secret',
        db: postgresAdapter({
          pool: { connectionString: `postgresql://identity_test@127.0.0.1:${port}/postgres` },
        }),
        admin: { disable: true },
        collections: [
          { slug: 'pg-users', auth: { disableLocalStrategy: true }, fields: [] },
          withAccountsCollection(
            {
              slug: 'pg-accounts',
              hooks: {
                beforeChange: [
                  ({ data }) => {
                    if (data.subject === 'fail-atomic') {
                      throw new Error('simulated account failure')
                    }
                  },
                ],
              },
            },
            { usersCollectionSlug: 'pg-users', realm: 'pg' },
          ),
        ],
        plugins: [authPlugin(config)],
      }),
    })
  }, 60_000)
  afterAll(async () => {
    if (payload) {
      type Client = { release: () => void }
      const pool = (
        payload.db as unknown as {
          pool: {
            _clients: Client[]
            _idle: { client: Client }[]
            end: () => Promise<void>
          }
        }
      ).pool
      await payload.destroy()
      // Payload 3.84.1 retains a monitor connection in its own pool. Release only this
      // fixture's checked-out connections after all operations settle, before pool shutdown.
      const idle = new Set(pool._idle.map(({ client }) => client))
      for (const client of pool._clients) {
        if (!idle.has(client)) {
          client.release()
        }
      }
      await pool.end()
    }
    if (isStarted) {
      execFileSync(
        join(binary, 'pg_ctl'),
        ['-D', join(directory, 'data'), '-m', 'fast', '-w', 'stop'],
        { stdio: 'pipe' },
      )
    }
    if (directory) {
      rmSync(directory, { recursive: true, force: true })
    }
  })

  it('creates atomic accounts and users, supports multiple identities and rejects revoked subjects', async () => {
    const session = { email: 'postgres@example.test', userId: 'postgres-uuid', emailVerified: true }
    const user = await resolveSSOUser({ payload, config, session })
    await linkAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: 'postgres-second' },
      userID: user.id,
      linkedBy: 'domain:1',
    })
    await linkAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: 'postgres-third' },
      userID: user.id,
      linkedBy: 'domain:third',
    })
    expect(
      (
        await resolveSSOUser({
          payload,
          config,
          session: { ...session, userId: 'postgres-second', email: 'new@example.test' },
        })
      ).id,
    ).toBe(user.id)
    await revokeAccountIdentity({
      payload,
      config,
      identity: { provider: 'central', subject: session.userId },
      linkedBy: 'domain:2',
    })
    await expect(resolveSSOUser({ payload, config, session })).rejects.toThrow('revoked')
  })

  it('rolls back the new user when account creation fails', async () => {
    await expect(
      resolveSSOUser({
        payload,
        config,
        session: { email: 'rollback@example.test', userId: 'fail-atomic', emailVerified: true },
      }),
    ).rejects.toThrow('simulated account failure')
    const users = await payload.find({
      collection: 'pg-users' as never,
      where: { email: { equals: 'rollback@example.test' } },
      overrideAccess: true,
    })
    expect(users.docs).toHaveLength(0)
  })

  it('arbitrates concurrent identical and different-subject legacy claims', async () => {
    const session = { email: 'pg-race@example.test', userId: 'pg-race', emailVerified: true }
    const results = await Promise.all(
      Array.from({ length: 3 }, () => resolveSSOUser({ payload, config, session })),
    )
    expect(new Set(results.map((user) => user.id)).size).toBe(1)
    await payload.create({
      collection: 'pg-users' as never,
      data: { email: 'pg-legacy@example.test' },
      overrideAccess: true,
    })
    const claims = await Promise.allSettled(
      ['one', 'two'].map((userId) =>
        resolveSSOUser({
          payload,
          config,
          session: { email: 'pg-legacy@example.test', userId, emailVerified: true },
        }),
      ),
    )
    expect(claims.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
  })
})
