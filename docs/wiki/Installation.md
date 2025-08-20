# Installation

Prerequisites:
- PHP 8.x
- Symfony 5.4/6.x
- A reachable Keycloak server (URL, realm, and client configured)

1) Install the bundle via Composer
- Packagist: zepekegno/keycloak-bundle

Example:
```bash
composer require zepekegno/keycloak-bundle
```

2) Import the bundle routes
Create config/routes/keycloak.yaml in your Symfony app:
```yaml
resource: '@KeycloakBundle/config/routes.yaml'
```

3) Configure security for your use case
- Web: ./Security-Web.md
- API/JWT: ./Security-API.md

4) Define Keycloak configuration
- See ./Configuration.md

5) Verify the flow
- Visit /login to start the authentication flow
- /callback is handled by the authenticator and redirects to /profile
- Use /logout to sign out

Tip:
- See docs/SETUP.md for a step-by-step guide with multi-environment examples.
