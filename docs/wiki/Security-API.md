# Security for APIs (JWT)

This page explains how to protect your API endpoints with Keycloak JWT using this bundle.

## Firewall Configuration

```yaml
# config/packages/security.yaml
security:
  providers:
    keycloak_provider:
      id: keycloak.user_provider

  firewalls:
    api:
      pattern: ^/api
      stateless: true
      provider: keycloak_provider
      custom_authenticators: keycloak.jwt_authenticator
      entry_point: keycloak.jwt_authenticator_entrypoint

  access_control:
    - { path: ^/api/public, roles: PUBLIC_ACCESS }
    - { path: ^/api, roles: ROLE_USER }
```

## Authentication Flow

- The authenticator `JwtAuthenticator` supports a request if an `Authorization: Bearer <token>` header is present.
- On success: the request continues; the user is available via Symfony’s Security component.
- On failure (invalid/expired token): it returns `401` with a JSON body describing the error.
- When no token is provided: the configured entrypoint `keycloak.jwt_authenticator_entrypoint` returns `401` with a JSON body.

## Common Responses

- Missing token: `{"error": "keycloak.jwt.missing_token"}`
- Invalid token: `{"error": "keycloak.jwt.invalid"}`
- Expired: `{"error": "keycloak.jwt.expired"}`

See also:
- Entrypoints: ./Entrypoints.md
- Troubleshooting: ./Troubleshooting.md