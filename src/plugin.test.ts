import { describe, it, expect } from 'vitest'
import type { Config } from 'payload'
import { authPlugin } from './plugin.js'
import { withAccountsCollection } from './collection/withAccountsCollection.js'

const sso = {
  cookieName: 'sso',
  loginUrl: 'https://example.test/login',
  logoutUrl: 'https://example.test/logout',
  jwt: { secret: 'test' },
}
const base = { name: 'admin', useAdmin: true, usersCollectionSlug: 'admin-users', sso }
const incoming: Config = {
  secret: 'test',
  db: {} as Config['db'],
  collections: [{ slug: 'admin-users', auth: { disableLocalStrategy: true }, fields: [] }],
}

describe('linked account plugin configuration', () => {
  it('keeps legacy consumers opt-out and preserves admin login/logout UI', () => {
    const config = authPlugin(base)(structuredClone(incoming))
    expect(config.collections).toHaveLength(1)
    expect(config.admin?.user).toBe('admin-users')
    expect(config.admin?.components?.afterLogin).toContainEqual(
      expect.objectContaining({ path: 'payload-auth-cookie/admin/DefaultSSOLoginButton' }),
    )
    expect(config.admin?.components?.views?.logout).toEqual(
      expect.objectContaining({ path: '/logout' }),
    )
    expect(config.endpoints?.map((endpoint) => endpoint.path)).toContain('/admin/auth/logout')
  })

  it('generates an immutable accounts collection with the matching realm and relationship', () => {
    const config = authPlugin({
      ...base,
      accountsCollectionSlug: 'admin-accounts',
      identity: { provider: 'central', subjectField: 'userId' },
    })(structuredClone(incoming))
    const accounts = config.collections?.find((collection) => collection.slug === 'admin-accounts')
    expect(accounts?.custom?.ssoAccounts).toEqual({
      usersCollectionSlug: 'admin-users',
      realm: 'admin',
    })
    expect(accounts?.fields).toContainEqual(
      expect.objectContaining({ name: 'user', relationTo: 'admin-users' }),
    )
    expect(accounts?.fields).toContainEqual(
      expect.objectContaining({ name: 'identityKey', unique: true, required: true }),
    )
    expect(accounts?.fields).toContainEqual(
      expect.objectContaining({ name: 'initialBindingKey', unique: true }),
    )
  })

  it('rejects half-configured or cross-realm account collections', () => {
    expect(() =>
      authPlugin({ ...base, accountsCollectionSlug: 'admin-accounts' })(incoming),
    ).toThrow('configured together')
    expect(() =>
      authPlugin({ ...base, identity: { provider: 'central', subjectField: 'userId' } })(incoming),
    ).toThrow('configured together')
    const accounts = withAccountsCollection(
      { slug: 'admin-accounts' },
      { usersCollectionSlug: 'app-users', realm: 'app' },
    )
    expect(() =>
      authPlugin({
        ...base,
        accountsCollectionSlug: 'admin-accounts',
        identity: { provider: 'central', subjectField: 'userId' },
      })({ ...incoming, collections: [...incoming.collections!, accounts] }),
    ).toThrow('matching user collection and realm')
  })

  it('enforces central-only linked auth without changing legacy local auth settings', () => {
    const linked = {
      ...base,
      accountsCollectionSlug: 'accounts',
      identity: { provider: 'central', subjectField: 'userId' },
    }
    const local = {
      ...incoming,
      collections: [{ slug: 'admin-users', auth: {}, fields: [] }],
    }
    const legacyAuth = authPlugin(base)(structuredClone(local)).collections![0].auth
    expect(legacyAuth).not.toHaveProperty('disableLocalStrategy')
    const linkedAuth = authPlugin(linked)(structuredClone(local)).collections![0].auth
    expect(linkedAuth).toMatchObject({ disableLocalStrategy: true })
    expect(() =>
      authPlugin(linked)({
        ...incoming,
        collections: [{ slug: 'admin-users', auth: false, fields: [] }],
      }),
    ).toThrow('auth-enabled')
    expect(() =>
      authPlugin(linked)({
        ...incoming,
        collections: [{ slug: 'admin-users', auth: { useAPIKey: true }, fields: [] }],
      }),
    ).toThrow('API-key')
  })

  it('rejects reserved identity field overrides and ignores caller-supplied mutation grants', () => {
    expect(() =>
      withAccountsCollection(
        { slug: 'accounts', fields: [{ name: 'subject', type: 'text' }] },
        { usersCollectionSlug: 'admin-users', realm: 'admin' },
      ),
    ).toThrow('cannot be overridden')
    const accounts = withAccountsCollection(
      { slug: 'accounts', access: { create: () => true, update: () => true, delete: () => true } },
      { usersCollectionSlug: 'admin-users', realm: 'admin' },
    )
    expect(accounts.access?.create?.({} as never)).toBe(false)
    expect(accounts.access?.update?.({} as never)).toBe(false)
    expect(accounts.access?.delete?.({} as never)).toBe(false)
  })
})
