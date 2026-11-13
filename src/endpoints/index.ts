import type { Endpoint, PayloadRequest } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import { handleSSOLogin } from '../lib/auth-handler.js'
import { parseCookies, validateSSOSession } from '../lib/sso-session.js'
import { resolveSSOUser, SSOAuthenticationError } from '../lib/identity-resolver.js'

/**
 * Get the base URL from the request
 */
function getBaseUrl(req: PayloadRequest): string {
  const host = req.headers.get('host')
  const protocol = req.headers.get('x-forwarded-proto') || 'http'

  if (host) {
    return `${protocol}://${host}`
  }

  return 'http://127.0.0.1:3000'
}

/**
 * Build the login URL with return URL parameter
 */
function buildLoginRedirectUrl(loginUrl: string, returnUrl: string): string {
  const url = new URL(loginUrl)
  url.searchParams.set('returnUrl', returnUrl)
  return url.toString()
}

/**
 * Create authentication endpoints for the plugin
 */
export function createAuthEndpoints(
  config: AuthPluginConfig,
  apiPrefix: string = '/api',
): Endpoint[] {
  const namespace = config.name

  const endpoints: Endpoint[] = [
    {
      path: `/${namespace}/auth/login`,
      method: 'get',
      handler: async (req) => {
        const headers = new Headers()
        const baseUrl = getBaseUrl(req)
        const loginUrl = config.sso.loginUrl

        const cookies = parseCookies(req.headers)
        const ssoCookie = cookies[config.sso.cookieName]

        if (!ssoCookie) {
          const returnUrl = `${baseUrl}${apiPrefix}/${namespace}/auth/login`
          const redirectUrl = buildLoginRedirectUrl(loginUrl, returnUrl)
          headers.set('Location', redirectUrl)
          return new Response(null, { status: 302, headers })
        }

        try {
          const session = await validateSSOSession(config.sso, ssoCookie)

          if (!session) {
            const returnUrl = `${baseUrl}${apiPrefix}/${namespace}/auth/login`
            const redirectUrl = buildLoginRedirectUrl(loginUrl, returnUrl)
            headers.set('Location', redirectUrl)
            return new Response(null, { status: 302, headers })
          }

          await handleSSOLogin(req.payload, config, session, req as unknown as Request)

          const redirectPath = config.successRedirectPath || '/'
          headers.set('Location', `${baseUrl}${redirectPath}`)
          return new Response(null, { status: 302, headers })
        } catch (error) {
          if (config.onError) {
            await config.onError({
              error: error as Error,
              req: req as unknown as Request,
            })
          }

          const errorPath = config.errorRedirectPath || '/auth/error'
          const errorMessage = error instanceof Error ? error.message : 'Authentication failed'

          let errorType = 'login_failed'
          if (errorMessage.includes('Sign-up is not allowed')) {
            errorType = 'signup_disabled'
          } else if (errorMessage.includes('SSO session missing email')) {
            errorType = 'invalid_session'
          }

          const returnUrl = `${apiPrefix}/${namespace}/auth/login`
          const errorUrl = `${baseUrl}${errorPath}?error=${errorType}&message=${encodeURIComponent(errorMessage)}&returnUrl=${encodeURIComponent(returnUrl)}`
          return Response.redirect(errorUrl, 302)
        }
      },
    },

    {
      path: `/${namespace}/auth/logout`,
      method: 'get',
      handler: async (req) => {
        const baseUrl = getBaseUrl(req)
        const returnUrl = config.useAdmin ? `${baseUrl}/admin/login` : `${baseUrl}/`
        const logoutUrl = config.sso.logoutUrl
        const redirectTo = buildLoginRedirectUrl(logoutUrl, returnUrl)

        return new Response(null, {
          status: 302,
          headers: { Location: redirectTo },
        })
      },
    },

    {
      path: `/${namespace}/auth/session`,
      method: 'get',
      handler: async (req) => {
        try {
          const user = await resolveRequestUser({ req, config })
          if (!user) {
            return Response.json({ authenticated: false })
          }

          return Response.json({
            user: {
              ...user,
              _strategy: 'sso-cookie',
              collection: config.usersCollectionSlug,
            },
            authenticated: true,
          })
        } catch (error) {
          console.error(`[payload-auth-cookie] Session check error for ${namespace}:`, error)
          return Response.json({ error: 'Failed to check session' }, { status: 500 })
        }
      },
    },
  ]

  // Payload admin bar calls /api/users/me (hardcoded) on every page load
  // This endpoint provides a compatible response to prevent errors
  // Only add this endpoint when useAdmin is true (for admin panel authentication)
  // Returns null user info if the logged-in user is from a non-admin collection
  if (config.useAdmin) {
    endpoints.push({
      path: '/users/me',
      method: 'get',
      handler: async (req) => {
        try {
          const isAdminUser = req.user && req.user.collection === config.usersCollectionSlug
          if (isAdminUser) {
            const user = config.accountsCollectionSlug
              ? await resolveRequestUser({ req, config })
              : req.user
            if (!user || String(user.id) !== String(req.user!.id)) {
              return Response.json({
                user: null,
                collection: config.usersCollectionSlug,
                token: null,
                exp: null,
              })
            }
            return Response.json({
              user,
              collection: config.usersCollectionSlug,
              token: null,
              exp: null,
            })
          } else {
            return Response.json({
              user: null,
              collection: config.usersCollectionSlug,
              token: null,
              exp: null,
            })
          }
        } catch (error) {
          console.error(`[payload-auth-cookie] /users/me error for ${namespace}:`, error)
          return Response.json(
            {
              user: null,
              collection: config.usersCollectionSlug,
              token: null,
              exp: null,
            },
            { status: 500 },
          )
        }
      },
    })
  }

  return endpoints
}

/** Inspect only established identities; neither session endpoint may provision or bootstrap. */
async function resolveRequestUser({
  req,
  config,
}: {
  req: PayloadRequest
  config: AuthPluginConfig
}) {
  const cookie = parseCookies(req.headers)[config.sso.cookieName]
  if (!cookie) {
    return null
  }
  const session = await validateSSOSession(config.sso, cookie)
  if (!session) {
    return null
  }
  try {
    return await resolveSSOUser({ payload: req.payload, config, session, allowProvisioning: false })
  } catch (error) {
    if (error instanceof SSOAuthenticationError) {
      return null
    }
    throw error
  }
}
