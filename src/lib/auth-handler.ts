import type { Payload } from 'payload'
import type { AuthPluginConfig } from '../types.js'
import type { SSOSessionData } from './sso-session.js'
import { resolveSSOUser } from './identity-resolver.js'

/** Resolve a validated central session and run the login callbacks. */
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
