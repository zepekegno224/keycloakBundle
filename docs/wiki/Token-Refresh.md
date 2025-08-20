# Token Refresh

Standard management:
- TokenRefreshService centralizes refresh logic; call it before operations that require a valid access_token (e.g., userinfo)
- Key methods:
  - refreshToken(session): attempts a refresh, updates access/refresh/id tokens + expiration
  - refreshTokenIfNeeded(session, margin=60): only refreshes when near expiration
  - getTokenStats(session): returns useful stats (expiration, remaining seconds, flags)

Expiration listener:
- The bundle registers a TokenExpirationListener event subscriber to check and, when needed, refresh/redirect (exact behavior depends on your setup and app logic)
- You can extend/disable/adjust it to fit your needs

Best practices:
- For APIs, prefer short-lived access tokens and a dedicated refresh flow
- For Web, refresh before hitting critical operations and clear session on refresh failure