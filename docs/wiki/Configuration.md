# Configuration

The bundle exposes the following keys (loaded via the bundle extension):

Required:
- keycloak.base_url: Base URL of your Keycloak server (e.g., https://sso.example.com)
- keycloak.realm: Realm name (e.g., my-realm)
- keycloak.client_id: Public OIDC client ID
- keycloak.client_secret: OIDC client secret (if required)
- keycloak.admin_client_id: Admin client ID for the administration API
- keycloak.admin_client_secret: Admin client secret for the administration API
- keycloak.public_key: Realm public key used to verify JWTs
- keycloak.algorithm: Signature algorithm (e.g., RS256)

Optional:
- keycloak.verify_token: Enable JWT verification (bool, default: true)
- keycloak.user_provider_service: Symfony UserProvider service ID (otherwise a simple Keycloak user is used)
- keycloak.redirect_routes: Post-auth redirects by role (map role -> route)
- keycloak.scope: OIDC scope (default: "openid profile email")

Example config/packages/keycloak.yaml:
```yaml
keycloak:
  base_url: '%env(KEYCLOAK_BASE_URL)%'
  realm: '%env(KEYCLOAK_REALM)%'
  client_id: '%env(KEYCLOAK_CLIENT_ID)%'
  client_secret: '%env(KEYCLOAK_CLIENT_SECRET)%'
  admin_client_id: '%env(KEYCLOAK_ADMIN_CLIENT_ID)%'
  admin_client_secret: '%env(KEYCLOAK_ADMIN_CLIENT_SECRET)%'
  public_key: '%env(resolve:KEYCLOAK_PUBLIC_KEY)%'
  verify_token: true
  algorithm: 'RS256'
  user_provider_service: null
  redirect_routes:
    ROLE_ADMIN: 'admin_dashboard'
    ROLE_USER: 'app_home'
  scope: 'openid profile email'
```

Notes:
- redirect_routes is used by an authentication success listener to send users to the right page based on roles.
- user_provider_service lets you integrate your own Symfony user-loading logic.