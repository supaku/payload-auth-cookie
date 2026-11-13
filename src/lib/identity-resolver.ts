import { createHash } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import type { Payload, PayloadRequest } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import type { SSOSessionData } from './sso-session.js'
import { getEmailFromSession, getNestedValue, hasVerifiedEmailForBinding } from './sso-session.js'
import { accountWriteContext } from './account-capability.js'

type User = Record<string, unknown> & { id: string | number }
export type AccountIdentity = { provider: string; subject: string }
type ResolverConfig = Pick<
  AuthPluginConfig,
  'name' | 'usersCollectionSlug' | 'accountsCollectionSlug' | 'identity' | 'allowSignUp'
>

/** Shared by the cookie strategy and login endpoint. The caller must validate the SSO session first. */
export async function resolveSSOUser({
  payload,
  config,
  session,
}: {
  payload: Payload
  config: ResolverConfig
  session: SSOSessionData
}): Promise<User> {
  if (!config.accountsCollectionSlug) {
    return resolveLegacyUser({ payload, config, session })
  }
  assertLinkedConfig(config)
  const subject = getNestedValue(session, config.identity!.subjectField)
  if (typeof subject !== 'string' || !subject.trim()) {
    throw new Error('SSO session missing stable subject')
  }
  const identity = { provider: config.identity!.provider, subject }
  const bound = await findAccount({ payload, config, identity })
  if (bound) {
    return authenticatedAccountUser({
      payload,
      config,
      account: bound,
      session,
    })
  }

  // Each attempt has an independent transaction. Database uniqueness, rather than an in-process
  // lock, arbitrates concurrent signups and migration claims across replicas/adapters.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const user = await transaction(payload, async (req) => {
        const existing = await findAccount({ payload, config, identity, req })
        if (existing) {
          return authenticatedAccountUser({
            payload,
            config,
            account: existing,
            session,
            req,
          })
        }
        const email = getEmailFromSession(session)
        if (!email) {
          throw new Error('SSO session missing email')
        }
        const matches = await payload.find({
          collection: config.usersCollectionSlug as never,
          where: { email: { equals: email } },
          limit: 2,
          pagination: false,
          depth: 0,
          overrideAccess: true,
          req,
        })
        let user = matches.docs[0] as User | undefined
        let provenance: string
        if (user) {
          if (
            matches.docs.length !== 1 ||
            user.email !== email ||
            !hasVerifiedEmailForBinding(session) ||
            !config.identity!.allowVerifiedEmailBootstrap
          ) {
            throw new Error('Existing user requires an explicit verified identity binding')
          }
          const prior = await payload.find({
            collection: config.accountsCollectionSlug as never,
            where: {
              and: [{ realm: { equals: config.name } }, { user: { equals: user.id } }],
            },
            limit: 1,
            pagination: false,
            depth: 0,
            overrideAccess: true,
            req,
          })
          if (prior.docs.length) {
            throw new Error('User already has an identity binding')
          }
          provenance = 'verified-email-bootstrap'
        } else {
          if (!config.allowSignUp) {
            throw new Error('Sign-up is not allowed')
          }
          user = (await payload.create({
            collection: config.usersCollectionSlug as never,
            data: { email, ...profileData(session) },
            overrideAccess: true,
            req,
          })) as User
          provenance = 'signup'
        }
        await createAccount({
          payload,
          config,
          identity,
          userID: user.id,
          provenance,
          linkedBy: `sso:${config.name}`,
          email,
          isInitial: true,
          req,
        })
        return attachIdentity(
          await updateProfile({ payload, config, user, session, req }),
          config,
          identity,
        )
      })
      // Some adapters do not propagate commit failures. Authentication requires a fresh read
      // proving the binding actually committed, rather than trusting the returned local object.
      const committed = await findAccount({ payload, config, identity })
      if (!committed || String(committed.user) !== String(user.id)) {
        throw new Error('Identity binding commit was not confirmed')
      }
      return authenticatedAccountUser({ payload, config, account: committed, session })
    } catch (error) {
      // A competing request may have committed this exact subject. A different subject never
      // inherits that binding: its initialBindingKey loses and the transaction rolls back.
      const winner = await findAccount({ payload, config, identity })
      if (winner) {
        return authenticatedAccountUser({
          payload,
          config,
          account: winner,
          session,
        })
      }
      if (attempt === 2 || !isRetryableConflict(error)) {
        throw error
      }
      await delay(10 * (attempt + 1))
    }
  }
  throw new Error('Identity binding failed')
}

/** Exact stable-identity lookup for cross-realm permission mapping. Never joins or merges by email. */
export async function findUserByIdentity({
  payload,
  config,
  identity,
}: {
  payload: Payload
  config: ResolverConfig
  identity: AccountIdentity
}): Promise<User | null> {
  assertLinkedConfig(config)
  const account = await findAccount({ payload, config, identity })
  if (!account || account.status !== 'active') {
    return null
  }
  return readAccountUser({ payload, config, account })
}

/**
 * Safely map an authenticated user's bound central identity into another local auth realm.
 * Metadata is only a lookup hint: source account ownership is checked again before the target
 * lookup. This confers no target business permissions; the calling domain must still authorize.
 */
export async function findUserForAuthenticatedIdentity({
  payload,
  sourceConfig,
  targetConfig,
  user,
}: {
  payload: Payload
  sourceConfig: ResolverConfig
  targetConfig: ResolverConfig
  user: { id: string | number; collection?: string; _ssoIdentity?: unknown }
}): Promise<User | null> {
  assertLinkedConfig(sourceConfig)
  assertLinkedConfig(targetConfig)
  const hint = user._ssoIdentity as Record<string, unknown> | undefined
  if (
    user.collection !== sourceConfig.usersCollectionSlug ||
    !hint ||
    hint.realm !== sourceConfig.name ||
    hint.provider !== sourceConfig.identity!.provider ||
    hint.provider !== targetConfig.identity!.provider ||
    typeof hint.subject !== 'string' ||
    !hint.subject.trim()
  ) {
    return null
  }
  const identity = { provider: hint.provider, subject: hint.subject }
  const source = await findUserByIdentity({ payload, config: sourceConfig, identity })
  if (!source || String(source.id) !== String(user.id)) {
    return null
  }
  return findUserByIdentity({ payload, config: targetConfig, identity })
}

/**
 * Server-only administrative operation. The calling application must authorize the actor and
 * independently prove ownership of the new identity. Never expose this as a generic endpoint.
 * Central SSO remains responsible for OAuth/provider linking and ownership proof.
 */
export async function linkAccountIdentity({
  payload,
  config,
  identity,
  userID,
  linkedBy,
}: {
  payload: Payload
  config: ResolverConfig
  identity: AccountIdentity
  userID: string | number
  /** Durable operator or domain command reference, supplied by trusted server code. */
  linkedBy: string
}): Promise<void> {
  assertLinkedConfig(config)
  if (!linkedBy.trim() || !identity.provider.trim() || !identity.subject.trim()) {
    throw new Error('Identity and audit provenance are required')
  }
  await transaction(payload, async (req) => {
    const existing = await findAccount({ payload, config, identity, req })
    if (existing) {
      throw new Error('Identity already bound; revoked identities cannot be reassigned')
    }
    const user = (await payload.findByID({
      collection: config.usersCollectionSlug as never,
      id: userID,
      depth: 0,
      overrideAccess: true,
      req,
    })) as User
    const prior = await payload.find({
      collection: config.accountsCollectionSlug as never,
      where: {
        and: [{ realm: { equals: config.name } }, { user: { equals: user.id } }],
      },
      limit: 1,
      pagination: false,
      depth: 0,
      overrideAccess: true,
      req,
    })
    await createAccount({
      payload,
      config,
      identity,
      userID,
      linkedBy,
      provenance: 'server-link',
      isInitial: !prior.docs.length,
      req,
    })
  })
  const committed = await findAccount({ payload, config, identity })
  if (!committed || committed.status !== 'active' || String(committed.user) !== String(userID)) {
    throw new Error('Identity link commit was not confirmed')
  }
}

/** Revocation retains the unique subject and initial-binding tombstone permanently. */
export async function revokeAccountIdentity({
  payload,
  config,
  identity,
  linkedBy,
}: {
  payload: Payload
  config: ResolverConfig
  identity: AccountIdentity
  linkedBy: string
}): Promise<void> {
  assertLinkedConfig(config)
  if (!linkedBy.trim()) {
    throw new Error('Audit provenance is required')
  }
  await transaction(payload, async (req) => {
    const account = await findAccount({ payload, config, identity, req })
    if (!account) {
      throw new Error('Identity not found')
    }
    await payload.update({
      collection: config.accountsCollectionSlug as never,
      id: account.id,
      data: { status: 'revoked', revokedBy: linkedBy, revokedAt: new Date().toISOString() },
      req,
      context: accountWriteContext(payload),
      overrideAccess: true,
    })
  })
  const committed = await findAccount({ payload, config, identity })
  if (!committed || committed.status !== 'revoked') {
    throw new Error('Identity revocation commit was not confirmed')
  }
}

export function assertLinkedConfig(config: ResolverConfig): void {
  if (
    !config.accountsCollectionSlug ||
    !config.identity?.provider.trim() ||
    !config.identity?.subjectField.trim()
  ) {
    throw new Error(
      'accountsCollectionSlug and identity.provider/subjectField must be configured together',
    )
  }
  if (!config.name.trim() || config.accountsCollectionSlug === config.usersCollectionSlug) {
    throw new Error('Invalid identity realm or collection')
  }
}

async function findAccount({
  payload,
  config,
  identity,
  req,
}: {
  payload: Payload
  config: ResolverConfig
  identity: AccountIdentity
  req?: Partial<PayloadRequest>
}): Promise<User | null> {
  const result = await payload.find({
    collection: config.accountsCollectionSlug as never,
    where: {
      identityKey: {
        equals: key([config.name, identity.provider, identity.subject]),
      },
    },
    depth: 0,
    limit: 2,
    pagination: false,
    overrideAccess: true,
    ...(req ? { req } : {}),
  })
  if (result.docs.length > 1) {
    throw new Error('Ambiguous identity binding')
  }
  const account = result.docs[0] as User | undefined
  if (
    account &&
    (account.realm !== config.name ||
      account.provider !== identity.provider ||
      account.subject !== identity.subject)
  ) {
    throw new Error('Invalid identity binding')
  }
  return account || null
}

async function readAccountUser({
  payload,
  config,
  account,
  req,
}: {
  payload: Payload
  config: ResolverConfig
  account: User
  req?: Partial<PayloadRequest>
}): Promise<User> {
  const id =
    typeof account.user === 'object' && account.user ? (account.user as User).id : account.user
  if (typeof id !== 'string' && typeof id !== 'number') {
    throw new Error('Identity has no linked user')
  }
  return (await payload.findByID({
    collection: config.usersCollectionSlug as never,
    id,
    depth: 0,
    overrideAccess: true,
    ...(req ? { req } : {}),
  })) as User
}

async function authenticatedAccountUser({
  payload,
  config,
  account,
  session,
  req,
}: {
  payload: Payload
  config: ResolverConfig
  account: User
  session: SSOSessionData
  req?: Partial<PayloadRequest>
}): Promise<User> {
  if (account.status !== 'active') {
    throw new Error('Identity has been revoked')
  }
  const user = await readAccountUser({ payload, config, account, req })
  return attachIdentity(await updateProfile({ payload, config, user, session, req }), config, {
    provider: account.provider as string,
    subject: account.subject as string,
  })
}

async function createAccount({
  payload,
  config,
  identity,
  userID,
  provenance,
  linkedBy,
  email,
  isInitial,
  req,
}: {
  payload: Payload
  config: ResolverConfig
  identity: AccountIdentity
  userID: string | number
  provenance: string
  linkedBy: string
  email?: string
  isInitial: boolean
  req: Partial<PayloadRequest>
}): Promise<void> {
  await payload.create({
    collection: config.accountsCollectionSlug as never,
    data: {
      identityKey: key([config.name, identity.provider, identity.subject]),
      ...(isInitial
        ? {
            initialBindingKey: key([config.name, config.usersCollectionSlug, String(userID)]),
          }
        : {}),
      realm: config.name,
      ...identity,
      user: userID,
      status: 'active',
      provenance,
      linkedBy,
      ...(email ? { emailAtBinding: email } : {}),
    },
    overrideAccess: true,
    req,
    context: accountWriteContext(payload),
  })
}

async function transaction<T>(
  payload: Payload,
  action: (req: Partial<PayloadRequest>) => Promise<T>,
): Promise<T> {
  const transactionID = await payload.db.beginTransaction()
  if (transactionID === null || transactionID === undefined) {
    throw new Error(
      'Identity binding requires database transactions (MongoDB replica set or transactional Postgres)',
    )
  }
  try {
    const result = await action({
      transactionID,
      context: accountWriteContext(payload),
    })
    await payload.db.commitTransaction(transactionID)
    return result
  } catch (error) {
    try {
      await payload.db.rollbackTransaction(transactionID)
    } catch {
      // Payload operations may already have rolled back their inherited transaction.
    }
    throw error
  }
}

function attachIdentity(user: User, config: ResolverConfig, identity: AccountIdentity): User {
  return { ...user, _ssoIdentity: { realm: config.name, ...identity } }
}

function key(parts: string[]): string {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex')
}

function isRetryableConflict(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error)
  return /unique|duplicate|conflict|writeconflict|serialization|deadlock/i.test(message)
}

function profileData(session: SSOSessionData): Record<string, unknown> {
  const data: Record<string, unknown> = {}
  for (const field of ['name', 'firstName', 'lastName', 'profilePictureUrl']) {
    if (typeof session[field] === 'string' && session[field]) {
      data[field] = session[field]
    }
  }
  if (session.emailVerified !== undefined) {
    data.emailVerified = session.emailVerified
  }
  if (session.lastLoginAt !== undefined) {
    data.lastLoginAt = session.lastLoginAt
  }
  return data
}

async function updateProfile({
  payload,
  config,
  user,
  session,
  req,
}: {
  payload: Payload
  config: ResolverConfig
  user: User
  session: SSOSessionData
  req?: Partial<PayloadRequest>
}): Promise<User> {
  const data = profileData(session)
  if (config.accountsCollectionSlug && getEmailFromSession(session) !== user.email) {
    delete data.emailVerified
  }
  for (const field of Object.keys(data)) {
    if (data[field] === user[field]) {
      delete data[field]
    }
  }
  if (!Object.keys(data).length) {
    return user
  }
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return (await payload.update({
        collection: config.usersCollectionSlug as never,
        id: user.id,
        data,
        overrideAccess: true,
        ...(req ? { req } : {}),
      })) as User
    } catch (error) {
      // An inherited transaction must be retried as a whole. A standalone profile sync may
      // retry its own transaction; it never changes the identity or email relationship.
      if (req || attempt === 2 || !isRetryableConflict(error)) {
        throw error
      }
      await delay(10 * (attempt + 1))
    }
  }
  throw new Error('Profile synchronization failed')
}

async function resolveLegacyUser({
  payload,
  config,
  session,
}: {
  payload: Payload
  config: ResolverConfig
  session: SSOSessionData
}): Promise<User> {
  const email = getEmailFromSession(session)
  if (!email) {
    throw new Error('SSO session missing email')
  }
  const users = await payload.find({
    collection: config.usersCollectionSlug as never,
    where: { email: { equals: email } },
    limit: 1,
    overrideAccess: true,
  })
  const user = users.docs[0] as User | undefined
  if (user) {
    return updateProfile({ payload, config, user, session })
  }
  if (!config.allowSignUp) {
    throw new Error('Sign-up is not allowed')
  }
  return (await payload.create({
    collection: config.usersCollectionSlug as never,
    data: { email, ...profileData(session) },
    overrideAccess: true,
  })) as User
}
