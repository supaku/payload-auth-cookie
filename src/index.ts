/**
 * Payload CMS Authentication Plugin for External SSO Cookie-Based Authentication
 *
 * This plugin provides seamless integration between Payload CMS and external SSO systems,
 * allowing you to authenticate users based on cookies set by an external SSO provider.
 *
 * @packageDocumentation
 */

export { authPlugin } from './plugin.js'
export type {
  AuthPluginConfig,
  SSOProviderConfig,
  JWTVerificationConfig,
  AuthPlugin,
  LinkedIdentityConfig,
} from './types.js'
export { createUsersCollection } from './collections/createUsersCollection.js'
export {
  generateUserToken,
  getExpiredPayloadCookie,
  getExpiredPayloadCookies,
  getPayloadCookie,
  getPayloadCookies,
} from './lib/session.js'
export { createCookieAuthStrategy } from './lib/strategy.js'
export {
  fetchSSOSession,
  getEmailFromSession,
  parseCookies,
  validateSSOConfig,
  validateSSOSession,
  verifyJWTSession,
} from './lib/sso-session.js'
export type { SSOSessionData } from './lib/sso-session.js'
export { createSSOProviderConfig } from './lib/helpers.js'

export { withUsersCollection } from './collection/index.js'

export { getAdminAuthCollection } from './utilities/getAdminAuthCollection.js'

export { withAccountsCollection, withAccountCollection } from './collection/index.js'
export {
  findUserByIdentity,
  findUserForAuthenticatedIdentity,
  linkAccountIdentity,
  revokeAccountIdentity,
} from './lib/identity-resolver.js'
export type { AccountIdentity } from './lib/identity-resolver.js'
