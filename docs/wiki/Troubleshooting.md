# Troubleshooting

Common issues (Web):
- keycloak.auth.missing_params: Code/state missing on callback. Ensure Keycloak redirects to /callback with all parameters.
- keycloak.auth.invalid_state: State doesn’t match session. Check session persistence and that no external redirects/reset occur.
- keycloak.auth.missing_code_verifier: The code_verifier was lost. Verify session, domain, and that /login initiated correctly.
- keycloak.auth.code_exchange_error: Code->token exchange failed. Verify client_id/secret, redirect_uri, and system clock skew.
- Invalid token after login: Verify keycloak.public_key, keycloak.algorithm, and that keycloak.verify_token is true.

Common issues (API):
- keycloak.jwt.missing_token: Add Authorization: Bearer <token>.
- keycloak.jwt.invalid: Wrong key/algorithm/public key, or malformed token.
- keycloak.jwt.expired: Refresh the token on the client or implement a refresh flow.
- keycloak.jwt.invalid_missing_user: sub claim missing; check the issued token.

HTTP/Keycloak:
- 401/403 from Keycloak: verify credentials and roles.
- 5xx on Admin calls: Keycloak-side issue; check server logs, connectivity, and admin client permissions.

Best practices:
- Keep server time in sync (NTP).
- In dev, ensure exact CORS/redirect_uri values.
- Log error responses in debug to diagnose issues quickly.