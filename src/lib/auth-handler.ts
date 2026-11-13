import type { Payload } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import type { SSOSessionData } from './sso-session.js'
import { resolveSSOUser } from './identity-resolver.js'

/**
 * Handle SSO login and create/update user in Payload
 *
 * This function takes the validated SSO session data and either:
 * 1. Finds an existing user by email and updates their profile
 * 2. Creates a new user if allowSignUp is enabled
 * 3. Throws an error if user doesn't exist and sign-up is disabled
 */
export async function handleSSOLogin(
  payload: Payload,
  config: AuthPluginConfig,
  session: SSOSessionData,
  req: Request,
): Promise<{
  user: Record<string, unknown> & { id: string | number }
}> {
  try {
    const user = await resolveSSOUser({ payload, config, session })

    if (config.onSuccess) {
      await config.onSuccess({
        user,
        session,
        req,
      })
    }

    return { user }
  } catch (error) {
    if (config.onError) {
      await config.onError({
        error: error as Error,
        req,
      })
    }
    throw error
  }
}
