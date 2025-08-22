# Configuration

This page summarizes the Keycloak bundle configuration and points to the full setup guide.

For the full step-by-step guide, see: ../SETUP.md

## 1) Bundle parameters

Define your Keycloak settings in config/packages/keycloak.yaml:

```yaml
keycloak:
  base_url: '%env(KEYCLOAK_BASE_URL)%'
  realm: '%env(KEYCLOAK_REALM)%'
  client_id: '%env(KEYCLOAK_CLIENT_ID)%'
  client_secret: '%env(KEYCLOAK_CLIENT_SECRET)%'
  admin_client_id: '%env(KEYCLOAK_ADMIN_CLIENT_ID)%'
  admin_client_secret: '%env(KEYCLOAK_ADMIN_CLIENT_SECRET)%'
  public_key: '%env(KEYCLOAK_PUBLIC_KEY)%'
  verify_token: true
  algorithm: 'RS256'
  user_provider_service: null
  redirect_routes: { }
  scope: 'openid profile email'
```

Environment variables example:

```env
KEYCLOAK_BASE_URL=https://your-keycloak.example.com
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-public-client
KEYCLOAK_CLIENT_SECRET=your-public-client-secret
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli-or-client
KEYCLOAK_ADMIN_CLIENT_SECRET=admin-client-secret
KEYCLOAK_PUBLIC_KEY=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
```

Notes:
- If you maintain your own UserProvider, set user_provider_service to its service ID; the bundle will alias keycloak.user_provider to your service.
- redirect_routes lets you define post-login target routes by role, e.g. ROLE_ADMIN -> admin_dashboard.

## 2) Import the bundle routes

Add a dedicated routes file and prefix:

```yaml
# config/routes/keycloak.yaml
keycloak_bundle:
  resource: '@KeycloakBundle/config/routes.yaml'
  prefix: /keycloak
```

For actual routes and names, see: ./Routes.md

## 3) Security configuration

- Web login (browser) firewall uses keycloak.authenticator with entry_point keycloak.authenticator_entrypoint.
- API firewall uses keycloak.jwt_authenticator with entry_point keycloak.jwt_authenticator_entrypoint and must be stateless.

See:
- ./Security-Web.md
- ./Security-API.md
- ./Entrypoints.md
