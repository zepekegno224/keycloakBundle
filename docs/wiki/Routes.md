# Routes

Import the bundle routes with a prefix:

```yaml
# config/routes/keycloak.yaml
keycloak_bundle:
  resource: '@KeycloakBundle/config/routes.yaml'
  prefix: /keycloak
```

The bundle exposes these routes (before prefix):

- keycloak_login → /login
- keycloak_callback → /callback
- keycloak_logout → /logout (GET/POST)
- keycloak_profile → /profile

With prefix /keycloak the final paths are:

- GET /keycloak/login → keycloak_login
- GET /keycloak/callback → keycloak_callback
- GET/POST /keycloak/logout → keycloak_logout
- GET /keycloak/profile → keycloak_profile

Tip:
- Add PUBLIC_ACCESS for these routes in your access_control to avoid redirect loops during login/callback.