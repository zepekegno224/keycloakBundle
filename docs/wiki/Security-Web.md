# Security — Web (Browser)

This page explains how to protect browser routes and enable Keycloak login flows.

## 1) Minimal web firewall

```yaml
# config/packages/security.yaml
security:
  enable_authenticator_manager: true

  providers:
    keycloak_provider:
      id: 'keycloak.user_provider'

  firewalls:
    dev:
      pattern: ^/(_(profiler|wdt)|css|images|js)/
      security: false

    main:
      lazy: true
      provider: keycloak_provider
      custom_authenticators:
        - keycloak.authenticator
      entry_point: keycloak.authenticator_entrypoint
      logout:
        path: keycloak_logout
        target: /

  access_control:
    # Allow public access to auth endpoints (prefix depends on your routes import)
    - { path: ^/keycloak/(login|callback|logout|profile), roles: PUBLIC_ACCESS }
    # Examples
    - { path: ^/admin, roles: ROLE_ADMIN }
    - { path: ^/dashboard, roles: IS_AUTHENTICATED_FULLY }
```

## 2) Flow

- Unauthenticated requests to protected pages are redirected to the Keycloak login route (via the web entrypoint).
- After successful login, the bundle processes the callback and authenticates the user in Symfony.
- You may configure post-login redirects via keycloak.redirect_routes (see Configuration.md).

## 3) Useful services

- keycloak.authenticator → Zepekegno\KeycloakBundle\Security\KeycloakAuthenticator
- keycloak.authenticator_entrypoint → Zepekegno\KeycloakBundle\Security\KeycloakAuthenticatorEntrypoint

See also:
- ./Entrypoints.md
- ./Routes.md
- ./Token-Refresh.md