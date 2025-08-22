# FAQ

## I get HTML or 302 redirects on my API endpoints

Make sure your API firewall uses the stateless JWT authenticator and the API entrypoint:

```yaml
security:
  firewalls:
    api:
      pattern: ^/api
      stateless: true
      custom_authenticators:
        - keycloak.jwt_authenticator
      entry_point: keycloak.jwt_authenticator_entrypoint
```

## How do I allow some public API routes?

```yaml
security:
  access_control:
    - { path: ^/api/public, roles: PUBLIC_ACCESS }
    - { path: ^/api, roles: ROLE_USER }
```

## Invalid or expired token errors

- Confirm the Authorization header is present: Authorization: Bearer <token>
- Check the realm public key and algorithm (KEYCLOAK_PUBLIC_KEY, RS256) in your configuration
- Ensure the token audience/roles match your access rules

## How to override the user provider?

Implement Symfony’s UserProviderInterface in your app and set keycloak.user_provider_service in config:

```yaml
keycloak:
  user_provider_service: 'app.my_user_provider'
```

The bundle will alias keycloak.user_provider to your service.

## How to change post-login redirection?

Use redirect_routes in keycloak.yaml:

```yaml
keycloak:
  redirect_routes:
    ROLE_ADMIN: 'admin_dashboard'
    ROLE_USER: 'dashboard'
```