import { describe, it, expect, vi, afterEach } from 'vitest'
import { SignJWT } from 'jose'
import type { Payload } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import {
  resolveSSOUser,
  findUserByIdentity,
  findUserForAuthenticatedIdentity,
  linkAccountIdentity,
  revokeAccountIdentity,
} from './identity-resolver.js'
import { createCookieAuthStrategy } from './strategy.js'
import { handleSSOLogin } from './auth-handler.js'
import { createAuthEndpoints } from '../endpoints/index.js'
import { verifyJWTSession, fetchSSOSession } from './sso-session.js'
import { withAccountsCollection } from '../collection/withAccountsCollection.js'

type Doc = Record<string, unknown> & { id: string }
type Args = {
  collection: string
  data?: Record<string, unknown>
  id?: string
  where?: Record<string, unknown>
  limit?: number
  req?: { transactionID?: number }
  context?: Record<string, unknown>
}
type State = Record<string, Doc[]>
const config: AuthPluginConfig = {
  name: 'app',
  usersCollectionSlug: 'app-users',
  accountsCollectionSlug: 'app-accounts',
  identity: {
    provider: 'supaku',
    subjectField: 'userId',
    allowVerifiedEmailBootstrap: true,
  },
  allowSignUp: false,
  sso: {
    cookieName: 'sso',
    loginUrl: 'https://accounts.example/login',
    logoutUrl: 'https://accounts.example/logout',
    jwt: { secret: 'test-secret' },
  },
}
const session = {
  email: 'seed@example.com',
  userId: 'central-uuid',
  emailVerified: true,
}
const seed = { id: 'user-1', email: session.email }
const request = new Request('https://app.example/api/app/auth/login')

// Serializable transaction model: no external database, user or provider state is touched.
// Unique indexes are enforced at commit as well as create, including concurrent transactions.
function fixture(initial: State = { 'app-users': [seed], 'app-accounts': [] }) {
  let state = structuredClone(initial)
  let next = 0
  let version = 0
  const transactions = new Map<number, { version: number; state: State }>()
  const view = (args: Args) =>
    args.req?.transactionID ? transactions.get(args.req.transactionID)!.state : state
  function matches(doc: Doc, where: Record<string, unknown>): boolean {
    return Object.entries(where).every(([field, condition]) =>
      field === 'and'
        ? (condition as Record<string, unknown>[]).every((clause) => matches(doc, clause))
        : doc[field] === (condition as { equals: unknown }).equals,
    )
  }
  function unique(data: State) {
    for (const [slug, docs] of Object.entries(data)) {
      for (const field of slug.endsWith('accounts')
        ? ['identityKey', 'initialBindingKey']
        : ['email']) {
        const values = docs.map((doc) => doc[field]).filter((value) => value !== undefined)
        if (new Set(values).size !== values.length) {
          throw new Error('unique conflict')
        }
      }
    }
  }
  const mock = {
    collections: {
      'app-users': { config: { auth: true } },
      'admin-users': { config: { auth: true } },
    },
    config: { csrf: [] },
    find: vi.fn(async (args: Args) => ({
      docs: (view(args)[args.collection] || [])
        .filter((doc) => !args.where || matches(doc, args.where))
        .slice(0, args.limit || 100)
        .map((doc) => structuredClone(doc)),
    })),
    findByID: vi.fn(async (args: Args) => {
      const doc = view(args)[args.collection]?.find((doc) => doc.id === args.id)
      if (!doc) {
        throw new Error('Missing user')
      }
      return structuredClone(doc)
    }),
    create: vi.fn(async (args: Args) => {
      const data = view(args)
      const doc = { ...args.data, id: `created-${++next}` }
      data[args.collection] ||= []
      data[args.collection].push(doc)
      unique(data)
      return structuredClone(doc)
    }),
    update: vi.fn(async (args: Args) => {
      const doc = view(args)[args.collection].find((doc) => doc.id === args.id)!
      Object.assign(doc, args.data)
      return structuredClone(doc)
    }),
    db: {
      beginTransaction: vi.fn(async () => {
        const id = ++next
        transactions.set(id, { version, state: structuredClone(state) })
        return id
      }),
      commitTransaction: vi.fn(async (id: number) => {
        const tx = transactions.get(id)!
        if (tx.version !== version) {
          throw new Error('serialization conflict')
        }
        unique(tx.state)
        state = tx.state
        version++
        transactions.delete(id)
      }),
      rollbackTransaction: vi.fn(async (id: number) => {
        transactions.delete(id)
      }),
    },
  }
  return { payload: mock as unknown as Payload, mock, state: () => state }
}

async function inspectSession({
  payload,
  authConfig = config,
  claims,
  user,
  path,
}: {
  payload: Payload
  authConfig?: AuthPluginConfig
  claims: Record<string, unknown>
  user?: Record<string, unknown>
  path?: string
}) {
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .sign(new TextEncoder().encode('test-secret'))
  const endpoint = createAuthEndpoints(authConfig).find(
    (entry) => entry.path === (path || `/${authConfig.name}/auth/session`),
  )!
  const response = await endpoint.handler({
    payload,
    user,
    headers: new Headers({ cookie: `sso=${token}` }),
  } as never)
  return {
    status: response.status,
    body: (await response.json()) as {
      authenticated?: boolean
      user?: Record<string, unknown> | null
      error?: string
    },
  }
}

afterEach(() => vi.unstubAllGlobals())

describe('stable linked identities', () => {
  it('bootstraps one verified exact email with signups closed; a stable subject survives changed email', async () => {
    const f = fixture()
    const first = await resolveSSOUser({ payload: f.payload, config, session })
    expect(first.id).toBe(seed.id)
    const second = await resolveSSOUser({
      payload: f.payload,
      config,
      session: { ...session, email: 'new@example.com' },
    })
    expect(second.id).toBe(seed.id)
    expect(second.email).toBe(seed.email)
    expect(f.state()['app-accounts'][0]).toMatchObject({
      provider: 'supaku',
      subject: session.userId,
      realm: 'app',
      provenance: 'verified-email-bootstrap',
      user: seed.id,
    })
  })

  it.each([false, undefined, 'true'])('rejects unverified bootstrap (%s)', async (verified) => {
    const f = fixture()
    await expect(
      resolveSSOUser({
        payload: f.payload,
        config,
        session: { ...session, emailVerified: verified as boolean },
      }),
    ).rejects.toThrow('explicit verified')
    expect(f.state()['app-accounts']).toHaveLength(0)
  })

  it('requires opt-in migration, and does not infer a subject from email', async () => {
    const f = fixture()
    await expect(
      resolveSSOUser({
        payload: f.payload,
        config: {
          ...config,
          identity: { ...config.identity!, allowVerifiedEmailBootstrap: false },
        },
        session,
      }),
    ).rejects.toThrow('explicit verified')
    await expect(
      resolveSSOUser({
        payload: f.payload,
        config,
        session: { email: seed.email },
      }),
    ).rejects.toThrow('stable subject')
  })

  it('rejects unknown users when closed; signup creates a user and account atomically when open', async () => {
    const f = fixture({ 'app-users': [], 'app-accounts': [] })
    await expect(resolveSSOUser({ payload: f.payload, config, session })).rejects.toThrow(
      'Sign-up is not allowed',
    )
    await resolveSSOUser({
      payload: f.payload,
      config: { ...config, allowSignUp: true },
      session,
    })
    expect(f.state()['app-users']).toHaveLength(1)
    expect(f.state()['app-accounts']).toHaveLength(1)
  })

  it('does not merge a second subject via email, including after revocation', async () => {
    const f = fixture()
    await resolveSSOUser({ payload: f.payload, config, session })
    const changed = { ...session, userId: 'different-subject' }
    await expect(resolveSSOUser({ payload: f.payload, config, session: changed })).rejects.toThrow(
      'already has',
    )
    await revokeAccountIdentity({
      payload: f.payload,
      config,
      identity: { provider: 'supaku', subject: session.userId },
      linkedBy: 'operator:1',
    })
    await expect(resolveSSOUser({ payload: f.payload, config, session })).rejects.toThrow('revoked')
    await expect(resolveSSOUser({ payload: f.payload, config, session: changed })).rejects.toThrow(
      'already has',
    )
    expect(
      await findUserByIdentity({
        payload: f.payload,
        config,
        identity: { provider: 'supaku', subject: session.userId },
      }),
    ).toBeNull()
  })

  it('supports explicit multiple identities and exact lookup without exposing credential fields', async () => {
    const f = fixture()
    await resolveSSOUser({ payload: f.payload, config, session })
    const identity = { provider: 'supaku', subject: 'second-central-uuid' }
    await linkAccountIdentity({
      payload: f.payload,
      config,
      identity,
      userID: seed.id,
      linkedBy: 'domain-command:123',
    })
    expect(
      (
        await resolveSSOUser({
          payload: f.payload,
          config,
          session: {
            ...session,
            userId: identity.subject,
            email: 'other@example.com',
          },
        })
      ).id,
    ).toBe(seed.id)
    expect((await findUserByIdentity({ payload: f.payload, config, identity }))?.id).toBe(seed.id)
    await expect(
      linkAccountIdentity({
        payload: f.payload,
        config,
        identity,
        userID: 'other',
        linkedBy: 'operator:2',
      }),
    ).rejects.toThrow('already bound')
    expect(Object.keys(f.state()['app-accounts'][1])).not.toContain('accessToken')
  })

  it('converges concurrent requests for the same subject onto one account', async () => {
    const f = fixture({ 'app-users': [], 'app-accounts': [] })
    const results = await Promise.all(
      Array.from({ length: 3 }, () =>
        resolveSSOUser({
          payload: f.payload,
          config: { ...config, allowSignUp: true },
          session,
        }),
      ),
    )
    expect(new Set(results.map((user) => user.id)).size).toBe(1)
    expect(f.state()['app-users']).toHaveLength(1)
    expect(f.state()['app-accounts']).toHaveLength(1)
  })

  it('lets only one competing subject bootstrap a legacy user', async () => {
    const f = fixture()
    const results = await Promise.allSettled(
      ['one', 'two'].map((userId) =>
        resolveSSOUser({
          payload: f.payload,
          config,
          session: { ...session, userId },
        }),
      ),
    )
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    expect(f.state()['app-accounts']).toHaveLength(1)
  })

  it('retries a labeled MongoDB transaction conflict without relying on its message', async () => {
    const f = fixture()
    const error = Object.assign(
      new Error('Caused by ::  :: Please retry your operation or multi-document transaction.'),
      { errorLabels: ['TransientTransactionError'] },
    )
    f.mock.create.mockRejectedValueOnce(error)
    expect((await resolveSSOUser({ payload: f.payload, config, session })).id).toBe(seed.id)
    expect(f.mock.db.beginTransaction).toHaveBeenCalledTimes(2)
    expect(f.mock.db.rollbackTransaction).toHaveBeenCalledTimes(1)
    expect(f.state()['app-accounts']).toHaveLength(1)
  })

  it('bounds retries when MongoDB continues reporting a transient transaction error', async () => {
    const f = fixture()
    const error = Object.assign(new Error('Please retry your multi-document transaction'), {
      errorLabels: ['TransientTransactionError'],
    })
    f.mock.create.mockRejectedValue(error)
    await expect(resolveSSOUser({ payload: f.payload, config, session })).rejects.toBe(error)
    expect(f.mock.db.beginTransaction).toHaveBeenCalledTimes(3)
    expect(f.mock.db.rollbackTransaction).toHaveBeenCalledTimes(3)
    expect(f.state()['app-accounts']).toHaveLength(0)
  })

  it.each([
    { errorLabels: ['UnknownTransactionCommitResult'] },
    {
      errorLabels: ['UnknownTransactionCommitResult', 'TransientTransactionError'],
    },
  ])(
    'does not restart a transaction after an unknown commit outcome: $errorLabels',
    async ({ errorLabels }) => {
      const f = fixture()
      const error = Object.assign(
        new Error('Transaction conflict with unconfirmed commit outcome'),
        {
          errorLabels,
        },
      )
      f.mock.db.commitTransaction.mockRejectedValueOnce(error)
      await expect(resolveSSOUser({ payload: f.payload, config, session })).rejects.toBe(error)
      expect(f.mock.db.beginTransaction).toHaveBeenCalledTimes(1)
      expect(f.mock.db.rollbackTransaction).toHaveBeenCalledTimes(1)
      expect(f.state()['app-accounts']).toHaveLength(0)
    },
  )

  it('rejects an adapter that returns from commit without persisting the binding', async () => {
    const f = fixture({ 'app-users': [], 'app-accounts': [] })
    f.mock.db.commitTransaction.mockImplementation(async () => {})
    await expect(
      resolveSSOUser({ payload: f.payload, config: { ...config, allowSignUp: true }, session }),
    ).rejects.toThrow('commit was not confirmed')
    expect(f.state()['app-users']).toHaveLength(0)
  })

  it('uses normalized mappings without accepting string verified claims or an explicitly unauthenticated central response', async () => {
    const token = await new SignJWT({
      ...session,
      emailVerified: 'true',
      email: 'untrusted-display@example.com',
      central: { email: seed.email },
    })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode('test-secret'))
    const verified = await verifyJWTSession(token, config.sso.jwt!, { emailField: 'central.email' })
    expect(verified?.email).toBe(seed.email)
    expect(verified?.emailVerified).toBe(true) // Legacy profile normalization is retained.
    const f = fixture()
    await expect(
      resolveSSOUser({ payload: f.payload, config, session: verified! }),
    ).rejects.toThrow('explicit verified')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json({ authenticated: false, user: session })),
    )
    expect(
      await fetchSSOSession({ ...config.sso, sessionUrl: 'https://example.test/me' }, 'test'),
    ).toBeNull()
  })

  it('rolls back a newly created user if account creation fails', async () => {
    const f = fixture({ 'app-users': [], 'app-accounts': [] })
    const create = f.mock.create.getMockImplementation()!
    f.mock.create.mockImplementation(async (args) => {
      if (args.collection === 'app-accounts') {
        throw new Error('simulated disk failure')
      }
      return create(args)
    })
    await expect(
      resolveSSOUser({
        payload: f.payload,
        config: { ...config, allowSignUp: true },
        session,
      }),
    ).rejects.toThrow('simulated disk failure')
    expect(f.state()['app-users']).toHaveLength(0)
    expect(f.state()['app-accounts']).toHaveLength(0)
  })

  it('fails closed on a nontransactional adapter', async () => {
    const f = fixture()
    f.mock.db.beginTransaction.mockResolvedValue(null as unknown as number)
    await expect(resolveSSOUser({ payload: f.payload, config, session })).rejects.toThrow(
      'requires database transactions',
    )
    expect(f.mock.create).not.toHaveBeenCalled()
  })

  it('isolates app/admin realms even for the same subject and email', async () => {
    const f = fixture({
      'app-users': [seed],
      'app-accounts': [],
      'admin-users': [{ ...seed, id: 'admin-1' }],
      'admin-accounts': [],
    })
    await resolveSSOUser({ payload: f.payload, config, session })
    const admin = {
      ...config,
      name: 'admin',
      usersCollectionSlug: 'admin-users',
      accountsCollectionSlug: 'admin-accounts',
    }
    expect((await resolveSSOUser({ payload: f.payload, config: admin, session })).id).toBe(
      'admin-1',
    )
    expect(
      (
        await findUserByIdentity({
          payload: f.payload,
          config,
          identity: { provider: 'supaku', subject: session.userId },
        })
      )?.id,
    ).toBe(seed.id)
  })

  it('revalidates source account ownership before mapping authenticated identity hints across realms', async () => {
    const f = fixture({
      'app-users': [seed],
      'app-accounts': [],
      'admin-users': [{ ...seed, id: 'admin-1' }],
      'admin-accounts': [],
    })
    const admin = {
      ...config,
      name: 'admin',
      usersCollectionSlug: 'admin-users',
      accountsCollectionSlug: 'admin-accounts',
    }
    await resolveSSOUser({ payload: f.payload, config, session })
    const user = {
      ...(await resolveSSOUser({ payload: f.payload, config: admin, session })),
      collection: 'admin-users',
    }
    const lookup = (candidate: Record<string, unknown> & { id: string | number }) =>
      findUserForAuthenticatedIdentity({
        payload: f.payload,
        sourceConfig: admin,
        targetConfig: config,
        user: candidate,
      })
    expect((await lookup(user))?.id).toBe(seed.id)
    expect(await lookup({ ...user, id: 'forged-user' })).toBeNull()
    expect(await lookup({ ...user, collection: 'app-users' })).toBeNull()
    for (const hint of [
      undefined,
      { realm: 'app', provider: 'supaku', subject: session.userId },
      { realm: 'admin', provider: 'evil', subject: session.userId },
      { realm: 'admin', provider: 'supaku', subject: 'unbound' },
    ]) {
      expect(await lookup({ ...user, _ssoIdentity: hint })).toBeNull()
    }
    await revokeAccountIdentity({
      payload: f.payload,
      config: admin,
      identity: { provider: 'supaku', subject: session.userId },
      linkedBy: 'operator:1',
    })
    expect(await lookup(user)).toBeNull()
  })

  it('uses the same subject mapping for JWT and unwrapped central session responses', async () => {
    const token = await new SignJWT(session)
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode('test-secret'))
    const jwt = await verifyJWTSession(token, config.sso.jwt!)
    expect(jwt?.userId).toBe(session.userId)
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          user: {
            id: session.userId,
            email: session.email,
            emailVerified: true,
          },
        }),
      ),
    )
    const fetched = await fetchSSOSession(
      { ...config.sso, sessionUrl: 'https://accounts.example/api/session/me' },
      'test',
    )
    const f = fixture()
    expect((await resolveSSOUser({ payload: f.payload, config, session: jwt! })).id).toBe(seed.id)
    expect(
      (
        await resolveSSOUser({
          payload: f.payload,
          config: {
            ...config,
            identity: { ...config.identity!, subjectField: 'id' },
          },
          session: fetched!,
        })
      ).id,
    ).toBe(seed.id)
  })

  it.each(['app', 'admin'])(
    'authenticates the %s strategy and namespaced login endpoint with the same resolver',
    async (realm) => {
      const f = fixture({
        'app-users': [seed],
        'app-accounts': [],
        'admin-users': [{ ...seed, id: 'admin-1' }],
        'admin-accounts': [],
      })
      const realmConfig = {
        ...config,
        name: realm,
        usersCollectionSlug: `${realm}-users`,
        accountsCollectionSlug: `${realm}-accounts`,
      }
      const expectedID = realm === 'app' ? seed.id : 'admin-1'
      const token = await new SignJWT(session)
        .setProtectedHeader({ alg: 'HS256' })
        .sign(new TextEncoder().encode('test-secret'))
      const headers = new Headers({ cookie: `sso=${token}`, host: 'app.example' })
      const strategy = createCookieAuthStrategy(
        realmConfig.usersCollectionSlug,
        config.sso,
        false,
        realmConfig,
      )
      expect((await strategy.authenticate({ payload: f.payload, headers })).user?.id).toBe(
        expectedID,
      )
      const endpoint = createAuthEndpoints(realmConfig).find(
        (endpoint) => endpoint.path === `/${realm}/auth/login`,
      )!
      const response = await endpoint.handler({ payload: f.payload, headers } as never)
      expect(response.status).toBe(302)
      expect(response.headers.get('location')).toBe('http://app.example/')
      expect(f.state()[realmConfig.accountsCollectionSlug]).toHaveLength(1)
      expect((await handleSSOLogin(f.payload, realmConfig, session, request)).user.id).toBe(
        expectedID,
      )
    },
  )

  it.each(['revoked', 'unbound'])(
    'session endpoint rejects a %s subject using a victim email without modifying the victim',
    async (state) => {
      const victim = { id: '99', email: 'victim@example.test', role: 'admin', name: 'Victim' }
      const attacker = { id: '1', email: 'attacker@example.test', name: 'Attacker' }
      const f = fixture({ 'app-users': [victim, attacker], 'app-accounts': [] })
      const identity = { provider: 'supaku', subject: 'revoked-attacker-subject' }
      if (state === 'revoked') {
        await linkAccountIdentity({
          payload: f.payload,
          config,
          identity,
          userID: attacker.id,
          linkedBy: 'seed:reviewer',
        })
        await revokeAccountIdentity({
          payload: f.payload,
          config,
          identity,
          linkedBy: 'revoke:reviewer',
        })
      }
      f.mock.find.mockClear()
      f.mock.update.mockClear()
      const token = await new SignJWT({
        userId: identity.subject,
        email: victim.email,
        name: 'attacker supplied',
        emailVerified: true,
      })
        .setProtectedHeader({ alg: 'HS256' })
        .sign(new TextEncoder().encode('test-secret'))
      const endpoint = createAuthEndpoints(config).find(
        (endpoint) => endpoint.path === '/app/auth/session',
      )!
      const response = await endpoint.handler({
        payload: f.payload,
        headers: new Headers({ cookie: `sso=${token}` }),
      } as never)
      expect(await response.json()).toEqual({ authenticated: false })
      expect(f.state()['app-users'].find((user) => user.id === victim.id)).toEqual(victim)
      expect(f.mock.update).not.toHaveBeenCalled()
      expect(f.mock.find.mock.calls.every(([args]) => args.collection === 'app-accounts')).toBe(
        true,
      )
    },
  )

  it.each(['app', 'admin'])(
    'session endpoint for %s follows the bound subject after email changes without selecting the email collision',
    async (realm) => {
      const owner = { id: 'bound', email: seed.email }
      const victim = { id: 'victim', email: 'new@example.test', role: 'admin', name: 'Victim' }
      const realmConfig = {
        ...config,
        name: realm,
        usersCollectionSlug: `${realm}-users`,
        accountsCollectionSlug: `${realm}-accounts`,
      }
      const f = fixture({ [`${realm}-users`]: [owner, victim], [`${realm}-accounts`]: [] })
      await linkAccountIdentity({
        payload: f.payload,
        config: realmConfig,
        identity: { provider: 'supaku', subject: session.userId },
        userID: owner.id,
        linkedBy: 'seed:binding',
      })
      f.mock.find.mockClear()
      const response = await inspectSession({
        payload: f.payload,
        authConfig: realmConfig,
        claims: { ...session, email: victim.email, name: 'Updated bound profile' },
      })
      expect(response.body.authenticated).toBe(true)
      expect(response.body.user).toMatchObject({
        id: owner.id,
        email: owner.email,
        name: 'Updated bound profile',
        _strategy: 'sso-cookie',
        collection: realmConfig.usersCollectionSlug,
      })
      expect(
        f.state()[realmConfig.usersCollectionSlug].find((user) => user.id === victim.id),
      ).toEqual(victim)
      expect(
        f.mock.find.mock.calls.every(
          ([args]) => args.collection === realmConfig.accountsCollectionSlug,
        ),
      ).toBe(true)
    },
  )

  it('session checks never provision users or verified-email bindings, including open signup mode', async () => {
    const f = fixture()
    const open = { ...config, allowSignUp: true, onSuccess: vi.fn(), onError: vi.fn() }
    for (const claims of [session, { ...session, email: 'new@example.test' }]) {
      expect((await inspectSession({ payload: f.payload, authConfig: open, claims })).body).toEqual(
        { authenticated: false },
      )
    }
    expect(f.mock.create).not.toHaveBeenCalled()
    expect(f.mock.db.beginTransaction).not.toHaveBeenCalled()
    expect(open.onSuccess).not.toHaveBeenCalled()
    expect(open.onError).not.toHaveBeenCalled()
  })

  it('session checks reject missing subjects and accounts from another realm', async () => {
    const f = fixture({
      'app-users': [seed],
      'app-accounts': [],
      'admin-users': [{ ...seed, id: 'admin' }],
      'admin-accounts': [],
    })
    await resolveSSOUser({ payload: f.payload, config, session })
    expect(
      (await inspectSession({ payload: f.payload, claims: { email: seed.email } })).body,
    ).toEqual({ authenticated: false })
    const admin = {
      ...config,
      name: 'admin',
      useAdmin: true,
      usersCollectionSlug: 'admin-users',
      accountsCollectionSlug: 'admin-accounts',
    }
    expect(
      (await inspectSession({ payload: f.payload, authConfig: admin, claims: session })).body,
    ).toEqual({ authenticated: false })
    expect(f.state()['admin-accounts']).toHaveLength(0)
  })

  it('legacy session checks preserve email/profile sync and never provision even when signup is open', async () => {
    const f = fixture()
    const legacy = {
      ...config,
      identity: undefined,
      accountsCollectionSlug: undefined,
      allowSignUp: true,
      onSuccess: vi.fn(),
      onError: vi.fn(),
    }
    const existing = await inspectSession({
      payload: f.payload,
      authConfig: legacy,
      claims: { email: seed.email, name: 'Legacy update' },
    })
    expect(existing.body).toMatchObject({
      authenticated: true,
      user: {
        id: seed.id,
        name: 'Legacy update',
        collection: 'app-users',
        _strategy: 'sso-cookie',
      },
    })
    expect(
      (
        await inspectSession({
          payload: f.payload,
          authConfig: legacy,
          claims: { email: 'missing@example.test' },
        })
      ).body,
    ).toEqual({ authenticated: false })
    expect(f.mock.create).not.toHaveBeenCalled()
    expect(legacy.onSuccess).not.toHaveBeenCalled()
    expect(legacy.onError).not.toHaveBeenCalled()
  })

  it('session infrastructure failures remain HTTP 500 rather than authenticating', async () => {
    const f = fixture()
    f.mock.find.mockRejectedValue(new Error('database unavailable'))
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const response = await inspectSession({ payload: f.payload, claims: session })
      expect(response.status).toBe(500)
      expect(response.body).toEqual({ error: 'Failed to check session' })
    } finally {
      log.mockRestore()
    }
  })

  it('linked /users/me rechecks central identity ownership and revocation instead of trusting stale req.user', async () => {
    const f = fixture({ 'admin-users': [seed], 'admin-accounts': [] })
    const admin = {
      ...config,
      name: 'admin',
      useAdmin: true,
      usersCollectionSlug: 'admin-users',
      accountsCollectionSlug: 'admin-accounts',
    }
    const bound = await resolveSSOUser({ payload: f.payload, config: admin, session })
    const user = { ...bound, collection: 'admin-users' }
    expect(
      (
        await inspectSession({
          payload: f.payload,
          authConfig: admin,
          claims: session,
          user,
          path: '/users/me',
        })
      ).body.user?.id,
    ).toBe(seed.id)
    expect(
      (
        await inspectSession({
          payload: f.payload,
          authConfig: admin,
          claims: session,
          user: { ...user, id: 'forged' },
          path: '/users/me',
        })
      ).body.user,
    ).toBeNull()
    await revokeAccountIdentity({
      payload: f.payload,
      config: admin,
      identity: { provider: 'supaku', subject: session.userId },
      linkedBy: 'revoke:mirror',
    })
    expect(
      (
        await inspectSession({
          payload: f.payload,
          authConfig: admin,
          claims: session,
          user,
          path: '/users/me',
        })
      ).body.user,
    ).toBeNull()
  })

  it('scopes native JWT fallback denial to the linked Payload instance and collection', async () => {
    const first = fixture()
    const other = fixture()
    const jwt = {
      name: 'local-jwt',
      authenticate: vi.fn(async (_args: { payload: Payload }) => ({
        user: { id: seed.id, collection: 'app-users' },
      })),
    }
    Object.assign(first.payload, { authStrategies: [jwt] })
    Object.assign(other.payload, { authStrategies: [jwt] })
    const linked = createCookieAuthStrategy('app-users', config.sso, false, config)
    await linked.authenticate({ payload: first.payload, headers: new Headers() })
    expect((await jwt.authenticate({ payload: first.payload })).user).toBeNull()
    expect((await jwt.authenticate({ payload: other.payload })).user?.id).toBe(seed.id)
  })

  it('rejects forged context grants and ordinary overrideAccess writes', () => {
    const accounts = withAccountsCollection(
      { slug: 'app-accounts' },
      { usersCollectionSlug: 'app-users', realm: 'app' },
    )
    const f = fixture()
    const hook = accounts.hooks!.beforeChange![0]
    for (const context of [{}, { ssoAccountCapability: {} }, { allowSSOAccountWrite: true }]) {
      expect(() => hook({ req: { payload: f.payload }, context } as never)).toThrow('server-side')
    }
    expect(() => accounts.hooks!.beforeDelete![0]({} as never)).toThrow('tombstones')
  })
})
