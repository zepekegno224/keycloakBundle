# Entrypoints (Web & API)

This bundle provides two entrypoints to handle unauthenticated requests appropriately depending on the context.

## Web (Browser) Entrypoint

- Service: `keycloak.authenticator_entrypoint`
- Class: `Zepekegno\KeycloakBundle\Security\KeycloakAuthenticatorEntrypoint`
- Behavior: redirects to the bundle’s login route

Routes import:
```yaml
# config/routes/keycloak.yaml
keycloak_bundle:
  resource: '@KeycloakBundle/config/routes.yaml'
  prefix: /auth
```

With the above, the entrypoint redirects to `keycloak_login`, which resolves to `/auth/login`.

Example (main firewall for web):
```yaml
# config/packages/security.yaml
security:
  firewalls:
    main:
      pattern: ^/
      provider: keycloak_provider
      custom_authenticators: keycloak.authenticator
      entry_point: keycloak.authenticator_entrypoint
```

## API (Stateless) Entrypoint

- Service: `keycloak.jwt_authenticator_entrypoint`
- Class: `Zepekegno\KeycloakBundle\Security\KeycloakJwtAuthenticatorEntrypoint`
- Behavior: returns HTTP 401 with a JSON body when no authentication was started (e.g., no Bearer token)

Use with the bundle’s JWT authenticator:
```yaml
# config/packages/security.yaml
security:
  firewalls:
    api:
      pattern: ^/api
      stateless: true
      custom_authenticators: keycloak.jwt_authenticator
      entry_point: keycloak.jwt_authenticator_entrypoint

  access_control:
    - { path: ^/api/public, roles: PUBLIC_ACCESS }
    - { path: ^/api, roles: ROLE_USER }
```

Notes:
- When a Bearer token is present but invalid/expired, `JwtAuthenticator` already returns a 401 JSON response.
- The API entrypoint covers the “no token” case to ensure consistent JSON 401 responses.
