# Security (API/JWT)

Goal: protect API endpoints using a Bearer JWT (Authorization: Bearer <token>), validated server-side.

1) Stateless API firewall
Example config/packages/security.yaml:
```yaml
security:
  enable_authenticator_manager: true

  providers:
    app_user_provider: { id: keycloak.user_provider } # or null if you use simple Keycloak user

  firewalls:
    api:
      pattern: ^/api
      stateless: true
      provider: app_user_provider
      custom_authenticators:
        - keycloak.jwt_authenticator

  access_control:
    - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }
```

2) Client usage
- Include header: Authorization: Bearer <access_token>
- JwtAuthenticator validates the token (signature, exp, sub, roles) via OIDCService and resolves the user (via your provider or a simple Keycloak user)

3) Common errors
- keycloak.jwt.missing_token: No bearer token found
- keycloak.jwt.invalid: Invalid signature/structure
- keycloak.jwt.expired: Token expired
- keycloak.jwt.invalid_missing_user: Missing sub claim

See ./Troubleshooting.md for solutions.