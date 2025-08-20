# Security (Web)

Goal: protect web pages by redirecting users to Keycloak (PKCE + state), then handle the callback and session.

1) Import the authentication routes
- config/routes/keycloak.yaml:
```yaml
resource: '@KeycloakBundle/config/routes.yaml'
```

Routes provided by the bundle:
- GET /login (redirects to Keycloak)
- GET /callback (authenticator entry point)
- GET /profile (example endpoint returning userinfo)
- GET/POST /logout

2) Configure your main firewall (e.g., main) in config/packages/security.yaml
```yaml
security:
  enable_authenticator_manager: true

  providers:
    app_user_provider: { id: keycloak.user_provider } # or your own provider

  firewalls:
    main:
      pattern: ^/
      lazy: true
      provider: app_user_provider
      custom_authenticators:
        - keycloak.authenticator
      logout:
        path: keycloak_logout
        target: keycloak_login

  access_control:
    - { path: ^/login, roles: PUBLIC_ACCESS }
    - { path: ^/callback, roles: PUBLIC_ACCESS }
    - { path: ^/profile, roles: IS_AUTHENTICATED_FULLY }
    - { path: ^/, roles: IS_AUTHENTICATED_FULLY }
```

3) Authentication flow
- User visits a protected page
- Redirect to /login
- /login generates code_verifier + state, then redirects to Keycloak (PKCE)
- On return to /callback, the authenticator exchanges the code for tokens, validates the JWT, stores session data, and authenticates the user
- Redirects to target path (if any) or profile

4) Post-auth redirects
- Use keycloak.redirect_routes in config to redirect based on roles (e.g., ROLE_ADMIN -> admin dashboard)

5) Logout
- /logout invalidates the local session and attempts to log out at Keycloak using the refresh_token when available

SSO:
- You can initiate silent SSO by calling /login?sso=1 (uses prompt=none on the authorization request).
