import type { Payload } from 'payload'
import type { AuthPluginConfig, SSOProviderConfig } from '../types.js'
import { resolveSSOUser } from './identity-resolver.js'
import { parseCookies, validateSSOSession } from './sso-session.js'

const guardedJWTStrategies = new WeakMap<object, WeakMap<Payload, Set<string>>>()

export interface CookieAuthStrategyOptions {
  collectionSlug: string
  ssoConfig: SSOProviderConfig
  allowSignUp?: boolean
}

/**
 * Cookie-based authentication strategy for Payload v3
 *
 * This strategy validates the external SSO cookie directly on each request,
 * completely bypassing Payload's built-in token/session system.
 *
 * When allowSignUp is true and a user doesn't exist, it will be created automatically.
 *
 * @param collectionSlug - The slug of the users collection
 * @param ssoConfig - SSO provider configuration for cookie validation
 * @param allowSignUp - Whether to create new users on first login
 */
export function createCookieAuthStrategy(
  collectionSlug: string,
  ssoConfig: SSOProviderConfig,
  allowSignUp?: boolean,
  identityOptions?: Pick<AuthPluginConfig, 'name' | 'accountsCollectionSlug' | 'identity'>,
) {
  return {
    name: `sso-cookie-${collectionSlug}`,
    authenticate: async ({ headers, payload }: { headers: Headers; payload: Payload }) => {
      try {
        if (identityOptions?.accountsCollectionSlug) {
          rejectLocalJWTFallback({ payload, collectionSlug })
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Payload's collections object uses dynamic keys
        const collection = (payload.collections as any)[collectionSlug]

        if (!collection || !collection.config.auth) {
          return { user: null }
        }

        const origin = headers.get('Origin')
        if (
          origin &&
          payload.config.csrf &&
          payload.config.csrf.length > 0 &&
          !payload.config.csrf.includes(origin)
        ) {
          return { user: null }
        }

        const cookies = parseCookies(headers)
        const ssoCookie = cookies[ssoConfig.cookieName]

        if (!ssoCookie) {
          return { user: null }
        }

        const session = await validateSSOSession(ssoConfig, ssoCookie)

        if (!session) {
          return { user: null }
        }

        const user = await resolveSSOUser({
          payload,
          config: {
            name: identityOptions?.name || collectionSlug,
            usersCollectionSlug: collectionSlug,
            allowSignUp,
            ...identityOptions,
          },
          session,
        })

        return {
          user: {
            ...user,
            _strategy: `sso-cookie-${collectionSlug}`,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Dynamic collection slug parameter for user augmentation
            collection: collectionSlug as any,
          },
        }
      } catch (error) {
        console.error(`[payload-auth-cookie] Strategy error for ${collectionSlug}:`, error)
        return { user: null }
      }
    },
  }
}

/** Payload's global JWT strategy does not honor a target collection's disableLocalStrategy. */
function rejectLocalJWTFallback({
  payload,
  collectionSlug,
}: {
  payload: Payload
  collectionSlug: string
}): void {
  const strategy = payload.authStrategies?.find((entry) => entry.name === 'local-jwt')
  if (!strategy) {
    return
  }
  let scopes = guardedJWTStrategies.get(strategy)
  if (!scopes) {
    scopes = new WeakMap<Payload, Set<string>>()
    guardedJWTStrategies.set(strategy, scopes)
    const blocked = scopes
    const authenticate = strategy.authenticate
    strategy.authenticate = async (args) => {
      const result = await authenticate(args)
      if (result.user && blocked.get(args.payload)?.has(result.user.collection)) {
        return { ...result, user: null }
      }
      return result
    }
  }
  const collections = scopes.get(payload) || new Set<string>()
  collections.add(collectionSlug)
  scopes.set(payload, collections)
}
