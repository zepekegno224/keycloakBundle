# Authentication Routes

The bundle provides 4 main routes (configured by default):

- /login (name: keycloak_login)
  - Redirects the user to Keycloak (PKCE + state), with optional SSO via the sso=1 query parameter
- /callback (name: keycloak_callback)
  - Authenticator entry point; exchanges the code for tokens, validates the JWT, and authenticates
- /profile (name: keycloak_profile)
  - Example endpoint: calls the userinfo endpoint with the session’s access_token; attempts a refresh if needed
- /logout (name: keycloak_logout)
  - Invalidates the local session and attempts Keycloak logout with the refresh_token

Tip:
- You can protect your own routes and use the session/roles set by the authenticator.
- Route names are also exposed via constants for internal use.