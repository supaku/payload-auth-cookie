# payload-auth-cookie

A Payload CMS authentication plugin for external SSO cookie-based authentication.

This plugin allows you to authenticate users based on cookies set by an external SSO system. It validates sessions via a configurable session endpoint and maps users to Payload CMS collections.

## Features

- 🍪 Cookie-based authentication from external SSO systems
- 🔑 JWT verification with configurable secret (no external API call needed)
- 🔐 Support for both admin panel and frontend authentication
- 👤 Automatic user creation with configurable sign-up policy
- 🔄 Session validation via external API or JWT verification
- 📦 TypeScript support with full type definitions

## Stable linked accounts (opt in)

Existing consumers keep email-based behavior unless `accountsCollectionSlug` and `identity` are
configured together. Linked mode authenticates the trusted central **provider + subject** in the
configured realm (`name`) before considering email. Central Supaku authentication stays authoritative;
local account rows store identity bindings and provenance, never OAuth access tokens, refresh tokens,
SSO cookies, or JWTs.

```ts
import { authPlugin, withAccountsCollection, withUsersCollection } from 'payload-auth-cookie'

const AppUsers = withUsersCollection({
  slug: 'app-users',
  auth: { disableLocalStrategy: true },
})
const AppAccounts = withAccountsCollection(
  { slug: 'app-accounts' },
  { usersCollectionSlug: AppUsers.slug, realm: 'app' },
)

const appAuth = {
  name: 'app',
  usersCollectionSlug: AppUsers.slug,
  accountsCollectionSlug: AppAccounts.slug,
  allowSignUp: process.env.SOCIAL_ALLOW_SIGNUPS === 'true',
  identity: {
    provider: 'supaku-account', // Fixed trusted namespace, never read from an untrusted request.
    subjectField: 'userId', // Central Supaku JWT's stable database UUID; NOT email or OAuth ID.
    allowVerifiedEmailBootstrap: false,
  },
  sso: {
    cookieName: 'supaku_session',
    loginUrl: 'https://account.supaku.com/login',
    logoutUrl: 'https://account.supaku.com/logout',
    jwt: { secret: process.env.SSO_JWT_SECRET! },
  },
}
// buildConfig({ collections: [AppUsers, AppAccounts], plugins: [authPlugin(appAuth)] })
```

For central `/api/session/me`, the existing session validator unwraps the returned `user` object.
Configure `identity.subjectField: 'id'` for that response instead of the JWT's `userId`. Both paths
require successfully validated central sessions. Dot paths are supported. Pin trusted issuer and
audience in `sso.jwt` when your central token contract provides those claims. The configured provider
namespace must be consistent across realms that intentionally share a central identity.

`withAccountCollection` is an alias for `withAccountsCollection`. The plugin creates the accounts
collection automatically if it is absent. An explicitly supplied collection must use the helper with
matching `usersCollectionSlug` and `realm`. Custom fields and read access are supported; reserved
identity fields cannot be overridden. Account create/update/delete access stays closed, including
ordinary Local API `overrideAccess: true` writes. Internal writes use an opaque Payload-instance
capability, so request context flags cannot grant mutation rights. Read defaults to the linked user
reading their own rows. Configure application-specific admin read access explicitly for visibility.

The cookie strategy, login endpoint, and session inspection handlers use the same identity resolver.
The `/{name}/auth/session` handler only inspects existing active bindings: it never creates users or
accounts or bootstraps by email. **Payload runs authentication strategies before endpoint handlers.**
Consequently a full session request may enroll an identity first when automatic signup or verified
bootstrap is explicitly enabled. This preserves existing automatic strategy enrollment behavior.
Closed signup never creates a new user; configured verified bootstrap may only bind an existing,
unlinked, exact-email user. A revoked or already-linked identity cannot be claimed by another subject.
In multi-auth installations, Payload stops after the first successful strategy; use the realm's explicit
`/{name}/auth/login` endpoint when that realm needs enrollment and an earlier realm already authenticated.
Legacy session handlers retain email/profile synchronization without creating missing users themselves.
Expected handler denials return `{ authenticated: false }`; infrastructure failures remain HTTP 500.
Session handlers do not invoke login callbacks.

Linked mode disables native local-password login and rejects native API-key configuration for its
user collection. Payload's global JWT fallback can otherwise target a linked collection in mixed-auth
installations; the linked cookie strategy filters those fallback results per Payload instance and
collection. Old or server-helper-minted Payload JWTs cannot substitute for central SSO. Unrelated local
collections keep their existing JWT authentication. The linked `/users/me` admin mirror also rechecks
the central session, active binding, and authenticated source user ID. Consumer-provided custom auth
strategies remain trusted server code and must uphold the same central identity policy.

### Migration, signup, linking, and revocation

- Existing active bindings authenticate even with `allowSignUp: false` or a changed display email.
  Email changes never change the user relationship or merge users. Local user email remains unchanged.
- Closed signup refuses unknown users. Open signup creates the local user and its first account in one
  transaction. A user email collision requires explicit binding; it never silently links another
  subject to an existing user.
- To migrate existing unlinked users, temporarily set `allowVerifiedEmailBootstrap: true`. It requires
  one exact stored email match and a boolean `emailVerified: true` from the validated mapped session.
  It works with closed signup. Unverified, ambiguous, and already-linked users are rejected.
- An immutable unique initial-binding tombstone prevents concurrent different subjects from claiming
  the same legacy user. Revocation retains this guard and the unique provider/subject reservation.
- For deliberate server-controlled linking, use
  `linkAccountIdentity({ payload, config: appAuth, userID, identity: { provider, subject }, linkedBy })`.
  The caller must authorize its domain command and independently prove ownership of the identity.
  Multiple identities may point to one user. No generic unauthenticated linking endpoint is installed.
  Central Supaku still owns OAuth provider linking, token storage, and ownership verification.
- Use `revokeAccountIdentity({ payload, config: appAuth, identity, linkedBy })` to revoke a binding.
  `linkedBy` identifies the trusted actor or domain command for this operation; the original link
  provenance is retained separately from `revokedBy` and `revokedAt`. Revocation is terminal through
  these APIs: rows cannot be deleted, reassigned, or reactivated by login/email bootstrap.

The plugin does not implement user hard-deletion or data-retention commands. Account tombstones retain
required user references. PostgreSQL may reject deleting bound users through FK/NOT NULL constraints;
MongoDB can leave dangling references, whose identities then fail closed when the user cannot be read.
Consumers should retain bound user records or define a reviewed domain retention policy. Disposable
test databases should use their harness-owned teardown rather than deleting identity tombstones.

Create the consumer's normal Payload migration **and JSON schema snapshot** for the new account
collection and its unique indexes before enabling linked mode in production. Existing user IDs stay
unchanged. The plugin does not migrate or touch central provider credentials. Migration bootstrap is
an explicit trust policy: enable it only when the central service reliably verifies email ownership,
then disable it after controlled migration. Alternatively seed bindings from a reviewed stable-ID
mapping using the server linking API, with no email bootstrap.

Binding creation, linking, and revocation require adapter transactions. MongoDB requires a replica set;
transaction-disabled adapters fail closed for mutations. Unique indexes arbitrate races across server
processes, and failed bindings roll back the associated user creation. A fresh lookup confirms the
binding after commit. Existing active bindings remain readable without a new binding transaction.
Queries inside binding transactions disable pagination to avoid parallel count/find operations on the
same MongoDB session. Application hooks must propagate `req` for their own transactional writes and
avoid external side effects that database rollback cannot undo.

### Mapping admin identity to app permissions

Linked authentication returns ephemeral `user._ssoIdentity = { realm, provider, subject }`. It contains
no token or cookie material. **Metadata alone is not authority.** The authenticated user must come
from Payload authentication; never accept a user/metadata object supplied by a client as proof.

```ts
import { findUserForAuthenticatedIdentity } from 'payload-auth-cookie'

const appUser = await findUserForAuthenticatedIdentity({
  payload: req.payload,
  sourceConfig: adminAuth,
  targetConfig: appAuth,
  user: req.user,
})
// Apply the actual app user's domain permissions and use the existing domain commands.
```

This helper validates the authenticated source collection, realm, configured provider, active source
binding, and source binding ownership against the user's ID before resolving the exact same central
provider/subject in the target realm. Forged hints, mismatched ownership, unbound or revoked subjects,
and provider mismatches return `null`. It does not combine multiple user identities or grant business
collection access. `findUserByIdentity({ payload, config, identity })` is a lower-level server-only exact
lookup; its caller is responsible for equivalent source authentication and domain authorization.

### Local verification

```sh
pnpm test:int --run
# Disposable local MongoDB replica set; never reads DATABASE_URI:
RUN_IDENTITY_ADAPTER_TESTS=1 pnpm test:int --run src/lib/identity-mongodb.test.ts
# Disposable local Postgres cluster using the dev workspace's pinned adapter:
RUN_IDENTITY_POSTGRES_TESTS=1 PG_TEST_BIN=/path/to/postgres/bin pnpm test:int --run src/lib/identity-postgres.test.ts
```

Adapter suites are opt in. They start/stop only isolated local fixture servers and never use application
connection strings. The Postgres suite defaults to Homebrew PostgreSQL 17 on macOS, allocates a free
loopback port, closes its own pool, stops its own cluster, and removes only its temporary directory.

## Installation

```bash
npm install payload-auth-cookie
# or
pnpm add payload-auth-cookie
# or
yarn add payload-auth-cookie
```

## Quick Start

### 1. Configure the Plugin

```typescript
// payload.config.ts
import { buildConfig } from 'payload'
import { authPlugin } from 'payload-auth-cookie'

export default buildConfig({
  plugins: [
    authPlugin({
      name: 'admin',
      useAdmin: true,
      usersCollectionSlug: 'adminUsers',
      successRedirectPath: '/admin',
      sso: {
        cookieName: process.env.SSO_COOKIE_NAME!,
        loginUrl: process.env.SSO_LOGIN_URL!,
        logoutUrl: process.env.SSO_LOGOUT_URL!,
        sessionUrl: process.env.SSO_SESSION_URL!,
      },
    }),
  ],
})
```

### 2. Create a Users Collection

```typescript
// collections/Users.ts
import { withUsersCollection } from 'payload-auth-cookie/collection'

export const AdminUsers = withUsersCollection({
  slug: 'adminUsers',
  auth: {
    disableLocalStrategy: true,
  },
  fields: [
    {
      name: 'name',
      type: 'text',
    },
  ],
})
```

### 3. Add Login Button to Admin Panel

```typescript
// components/SSOLoginButton.tsx
'use client'

import { LoginButton } from 'payload-auth-cookie/client'

export default function SSOLoginButton() {
  return <LoginButton href="/api/admin/auth/login" label="Sign in with SSO" />
}
```

```typescript
// payload.config.ts
export default buildConfig({
  admin: {
    components: {
      afterLogin: ['@/components/SSOLoginButton'],
    },
  },
  // ...
})
```

## Configuration

### Plugin Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `name` | `string` | ✅ | - | Unique name for this auth configuration (used in endpoint paths) |
| `usersCollectionSlug` | `string` | ✅ | - | Slug of the users collection to authenticate against |
| `sso` | `SSOProviderConfig` | ✅ | - | SSO provider configuration |
| `useAdmin` | `boolean` | ❌ | `false` | Use this configuration for admin panel authentication |
| `allowSignUp` | `boolean` | ❌ | `false` | Allow creating new users on first login |
| `successRedirectPath` | `string` | ❌ | `'/'` | Path to redirect after successful authentication |
| `errorRedirectPath` | `string` | ❌ | `'/auth/error'` | Path to redirect on authentication error |
| `onSuccess` | `function` | ❌ | - | Callback after successful authentication |
| `onError` | `function` | ❌ | - | Callback on authentication error |

### SSO Provider Configuration

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `cookieName` | `string` | ✅ | - | Name of the cookie set by your SSO system |
| `loginUrl` | `string` | ✅ | - | URL to redirect for SSO login |
| `logoutUrl` | `string` | ✅ | - | URL to redirect for SSO logout |
| `sessionUrl` | `string` | ⚠️ | - | URL to validate session (required if `jwt` not provided) |
| `jwt` | `JWTVerificationConfig` | ⚠️ | - | JWT verification config (required if `sessionUrl` not provided) |
| `timeoutMs` | `number` | ❌ | `5000` | Timeout for session validation requests |

### JWT Verification Configuration

When your SSO cookie contains a JWT, you can verify it locally without calling an external session endpoint:

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `secret` | `string` | ✅ | - | Secret key for verifying JWT signatures |
| `algorithm` | `string` | ❌ | `'HS256'` | JWT algorithm (`HS256`, `HS384`, `HS512`) |
| `issuer` | `string` | ❌ | - | Expected issuer (iss claim) |
| `audience` | `string` | ❌ | - | Expected audience (aud claim) |
| `emailField` | `string` | ❌ | `'email'` | Field path to extract email (supports dot notation) |
| `firstNameField` | `string` | ❌ | `'firstName'` | Field path to extract first name |
| `lastNameField` | `string` | ❌ | `'lastName'` | Field path to extract last name |
| `profilePictureUrlField` | `string` | ❌ | `'profilePictureUrl'` | Field path to extract profile picture URL |

### Field Mappings

Map SSO response fields to your collection's field names:

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `fieldMappings.nameField` | `string` | ❌ | `'name'` | SSO field containing the user's full name |
| `fieldMappings.firstNameField` | `string` | ❌ | `'firstName'` | SSO field containing the user's first name |
| `fieldMappings.lastNameField` | `string` | ❌ | `'lastName'` | SSO field containing the user's last name |
| `fieldMappings.profilePictureUrlField` | `string` | ❌ | `'profilePictureUrl'` | SSO field containing the profile picture URL |
| `fieldMappings.emailVerifiedField` | `string` | ❌ | `'emailVerified'` | SSO field indicating email verification status |
| `fieldMappings.lastLoginAtField` | `string` | ❌ | `'lastLoginAt'` | SSO field containing last login timestamp |

#### Field Mappings Example

```typescript
authPlugin({
  name: 'app',
  usersCollectionSlug: 'appUsers',
  sso: {
    cookieName: 'sso_token',
    loginUrl: 'https://sso.example.com/login',
    logoutUrl: 'https://sso.example.com/logout',
    jwt: {
      secret: process.env.SSO_JWT_SECRET!,
    },
    fieldMappings: {
      nameField: 'full_name',           // Maps SSO's full_name → user.name
      profilePictureUrlField: 'avatar', // Maps SSO's avatar → user.profilePictureUrl
    },
  },
})
```

#### JWT Configuration Example

```typescript
authPlugin({
  name: 'admin',
  useAdmin: true,
  usersCollectionSlug: 'adminUsers',
  sso: {
    cookieName: 'sso_token',
    loginUrl: 'https://sso.example.com/login',
    logoutUrl: 'https://sso.example.com/logout',
    jwt: {
      secret: process.env.SSO_JWT_SECRET!,
      algorithm: 'HS256',
      issuer: 'https://sso.example.com',
      emailField: 'user.email',  // For nested JWT payloads
    },
  },
})
```

## Authentication Flow

### Admin Login Flow

1. User navigates to `/admin`
2. If not authenticated, clicks "Sign in with SSO" button
3. Plugin redirects to `loginUrl` with `returnUrl` parameter
4. User authenticates with external SSO
5. SSO system sets a cookie (e.g., `supaku_session`)
6. User is redirected back to `/api/admin/auth/login`
7. Plugin validates cookie via `sessionUrl` or JWT verification
8. Plugin finds/creates user and sets Payload session cookie
9. User is redirected to `/admin`

### Frontend Login Flow

1. User navigates to `/auth/login` (or custom login page)
2. App redirects to `/api/app/auth/login`
3. If no SSO cookie, redirects to `loginUrl`
4. After SSO authentication, user returns with cookie
5. Plugin validates and creates session
6. User is redirected to success path

## Session Validation Methods

### Method 1: Session URL (API-based)

Your SSO session endpoint (`sessionUrl`) should:

1. Accept the SSO cookie in the request
2. Return JSON with at least an `email` field
3. Return 200 OK for valid sessions
4. Return non-2xx for invalid/expired sessions

#### Expected Response Format

The plugin supports multiple response formats:

**Direct user data:**
```json
{
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "profilePictureUrl": "https://example.com/avatar.jpg"
}
```

**Nested user object (automatically extracted):**
```json
{
  "authenticated": true,
  "user": {
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "profilePictureUrl": "https://example.com/avatar.jpg"
  }
}
```

### Method 2: JWT Verification (Local)

If your SSO cookie is a JWT, configure `jwt` instead of `sessionUrl`:

```typescript
sso: {
  cookieName: 'sso_token',
  loginUrl: 'https://sso.example.com/login',
  logoutUrl: 'https://sso.example.com/logout',
  jwt: {
    secret: process.env.SSO_JWT_SECRET!,
  },
}
```

The JWT payload should contain at least an `email` field (configurable via `emailField`).

## Multiple Auth Instances

You can configure multiple auth instances for different user types. Each instance creates its own set of endpoints and correctly returns users from its associated collection:

```typescript
plugins: [
  authPlugin({
    name: 'admin',
    useAdmin: true,
    usersCollectionSlug: 'adminUsers',
    successRedirectPath: '/admin',
    sso: adminSSOConfig,
  }),
  authPlugin({
    name: 'app',
    allowSignUp: true,
    usersCollectionSlug: 'appUsers',
    successRedirectPath: '/',
    sso: appSSOConfig,
  }),
]
```

With this configuration:

- `/api/admin/auth/session` returns users from `adminUsers` collection
- `/api/app/auth/session` returns users from `appUsers` collection
- Each endpoint syncs SSO data to its own collection's user records
- Authentication strategies are uniquely named (`sso-cookie-adminUsers`, `sso-cookie-appUsers`)

## API Endpoints

The plugin creates the following endpoints (prefixed with your configured `name`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/{name}/auth/login` | GET | Initiates login or validates SSO cookie |
| `/api/{name}/auth/logout` | GET | Clears session and redirects to SSO logout |
| `/api/{name}/auth/session` | GET | Returns current session status |
| `/api/users/me` | GET | Returns current user (for Payload admin bar compatibility) |

### Admin Bar Compatibility

The plugin automatically adds a `/api/users/me` endpoint to support the Payload admin bar, which expects this endpoint to exist. This works around an issue where Payload calls `/api/users/me` on every page load even when `disableLocalStrategy: true` is set on the users collection.

## Helper Functions

### Server-Side

```typescript
import {
  validateSSOSession,
  verifyJWTSession,
  fetchSSOSession,
  getEmailFromSession,
  parseCookies,
  generateUserToken,
} from 'payload-auth-cookie'
```

### Client-Side

```typescript
import { LoginButton, AuthProvider, useAuth } from 'payload-auth-cookie/client'
```

## Environment Variables

```env
# Common
SSO_COOKIE_NAME=supaku_session
SSO_LOGIN_URL=https://sso.example.com/login
SSO_LOGOUT_URL=https://sso.example.com/logout

# For Session URL validation
SSO_SESSION_URL=https://sso.example.com/api/session

# For JWT verification (alternative to SESSION_URL)
SSO_JWT_SECRET=your-jwt-signing-secret
```

## License

MIT
