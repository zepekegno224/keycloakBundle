# Services

The bundle exposes public services and convenient aliases.

Aliases:
- keycloak.oidc_service -> OIDC service (OIDC auth, tokens, userinfo, logout)
- keycloak.admin_service -> Admin API service (users and roles management)
- keycloak.token_refresh_service -> Token refresh management
- keycloak.authenticator -> Web authenticator (PKCE/state)
- keycloak.jwt_authenticator -> API authenticator (Bearer JWT)

OIDCService (keycloak.oidc_service):
- generateCodeVerifier(length=64): string — Generates a PKCE code_verifier
- getLoginUrl(codeVerifier, state, params=[]): string — Authorization URL to Keycloak (callback is auto-generated)
- getSsoLoginUrl(codeVerifier, state): string — Same with prompt=none
- exchangeCode(code, codeVerifier): array — Exchanges the code for tokens (access, refresh, id)
- refreshToken(refreshToken): array — Refreshes the access_token
- getUserInfo(accessToken): array — Calls /userinfo
- validateToken(token): ?array — Verifies the signature (if verify_token=true) and returns the payload
- logout(refreshToken): bool — Logs out from Keycloak using the refresh token
- extractBearerToken(Request): ?string — Extracts the Bearer token from the Authorization header

TokenRefreshService (keycloak.token_refresh_service):
- isTokenNearExpiration(session, margin=60): bool
- isTokenExpired(session): bool
- refreshToken(session): RefreshResult — Attempts refresh and updates session tokens
- refreshTokenIfNeeded(session, margin=60): RefreshResult — Refreshes only when near expiration
- clearKeycloakSession(session, reason='...'): void
- getTokenStats(session): array — Useful info (expiration, flags)

KeycloakAdminService (keycloak.admin_service):
- getAdminToken(): string — Retrieves/renews an admin token (client_credentials)
- createUser(data, realmRoles, clientRoles, password, attributes=[], requiredActions=['VERIFY_EMAIL']): string — Creates a user and assigns roles
- assignRolesToUser(userId, roles): void — Assigns realm roles
- assignClientRolesToUser(userId, roles): void — Assigns client roles (for the configured client_id)

Usage examples (controller/service in your app):
```php
// Fetch userinfo with session token (Web)
$userInfo = $oidcService->getUserInfo($session->get('keycloak_access_token'));

// Refresh if needed
$result = $tokenRefreshService->refreshTokenIfNeeded($session);

// Admin API: create a user
$userId = $admin->createUser(
    ['username' => 'jdoe', 'email' => 'j@ex.com'],
    ['ROLE_USER'],
    ['user-app-role'],
    'P@ssw0rd!'
);
```