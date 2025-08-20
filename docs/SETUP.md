# Zepekegno Keycloak Bundle — Full Setup Guide

This guide walks you through installing and configuring the Zepekegno Keycloak Bundle in a Symfony 6 application.

## Requirements

- PHP >= 8.0
- Symfony >= 6.0
- A Keycloak server (base URL, realm, and a configured client)

## 1. Install

```bash
composer require zepekegno/keycloak-bundle
```

If Symfony Flex does not auto-enable the bundle, add it to config/bundles.php:

```php
return [
    // ... existing code ...
    Zepekegno\KeycloakBundle\KeycloakBundle::class => ['all' => true],
];
```

## 2. Configure Keycloak parameters

Create config/packages/keycloak.yaml:

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
  # If you have your own user provider, set its service ID here, otherwise leave null
  user_provider_service: null
  # Optional: post-login redirects by role
  redirect_routes:
    ROLE_ADMIN: 'admin_dashboard'
    ROLE_USER: 'dashboard'
  scope: 'openid profile email'
```

Add environment variables (.env, or Symfony secrets):

```env
KEYCLOAK_BASE_URL=https://your-keycloak.example.com
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-public-client
KEYCLOAK_CLIENT_SECRET=your-public-client-secret
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli-or-client
KEYCLOAK_ADMIN_CLIENT_SECRET=admin-client-secret
# PEM content without headers or one-line base64 without spaces (depends on how you store it)
KEYCLOAK_PUBLIC_KEY=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
```

Configuration reference (from the bundle’s config tree):
- base_url (string, required): Keycloak server base URL
- realm (string, required): Keycloak realm name
- client_id (string, required): OIDC public client ID
- client_secret (string, required): OIDC client secret
- admin_client_id (string, required): Admin API client ID
- admin_client_secret (string, required): Admin API client secret
- public_key (string, required): Realm public key to verify JWT
- verify_token (bool, default: true): Enable JWT verification
- algorithm (string, required): JWT signing algorithm (e.g. RS256)
- user_provider_service (string|null, default: null): Symfony user provider service ID
- redirect_routes (map<string,string>, default: {}): Post-login redirect route names by role
- scope (string, default: "openid profile email")

## 3. Import bundle routes

Create config/routes/keycloak.yaml:

```yaml
keycloak_bundle:
  resource: '@KeycloakBundle/config/routes.yaml'
  prefix: /keycloak
```

This exposes:
- GET /keycloak/login → keycloak_login
- GET /keycloak/callback → keycloak_callback
- GET/POST /keycloak/logout → keycloak_logout
- GET /keycloak/profile → keycloak_profile

You can change the prefix to suit your app.

## 4. Configure Symfony Security

Minimal web login (session) with KeycloakAuthenticator:

```yaml
# config/packages/security.yaml
security:
  enable_authenticator_manager: true

  providers:
    app_user_provider:
      # Use bundle default user provider alias (can be overridden by user_provider_service)
      id: 'keycloak.user_provider'

  firewalls:
    dev:
      pattern: ^/(_(profiler|wdt)|css|images|js)/
      security: false

    main:
      lazy: true
      provider: app_user_provider
      custom_authenticators:
        - keycloak.authenticator
      # Optional logout handler (route provided by the bundle)
      logout:
        path: keycloak_logout
        target: /

  access_control:
    # Allow public access to auth endpoints
    - { path: ^/keycloak/(login|callback|logout|profile), roles: PUBLIC_ACCESS }
    # Example restrictions
    - { path: ^/admin, roles: ROLE_ADMIN }
    - { path: ^/dashboard, roles: IS_AUTHENTICATED_FULLY }
```

API protection with JwtAuthenticator (stateless):

```yaml
# config/packages/security.yaml
security:
  # ... existing code ...
  firewalls:
    # ... existing code ...
    api:
      pattern: ^/api
      stateless: true
      custom_authenticators:
        - keycloak.jwt_authenticator

  access_control:
    - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }
```

Notes:
- keycloak.authenticator (web) redirects to Keycloak when authentication fails.
- keycloak.jwt_authenticator (API) validates Bearer tokens and returns 401 JSON on failure.

## 5. Usage

Login flow:
- Protect your pages via access_control and link to the login route if you want: {{ path('keycloak_login') }}.
- User is redirected to Keycloak, then back to keycloak_callback where the bundle exchanges the code for tokens and authenticates the user.

Session keys you may read (see Constants):
- Access token, refresh token, id token, expiration, user data, state, code verifier.

Profile route:
- GET /keycloak/profile shows decoded token data (via the provided controller).

Logout:
- GET/POST /keycloak/logout → ends the session and redirects.

## 6. Token refresh

- TokenExpirationListener automatically checks token expiration on each request and triggers refresh via TokenRefreshService when possible.
- You can also call TokenRefreshService directly:
  - refreshTokens(refreshToken): array
  - refreshTokensWithRetry(refreshToken, maxRetries): array
  - updateSessionTokens(session, tokens): void

## 7. Admin API examples

```php
<?php
// e.g., in a controller or service
use Zepekegno\KeycloakBundle\Service\KeycloakAdminService;

/** @var KeycloakAdminService $admin */
$admin = $this->container->get('keycloak.admin_service');

$userId = $admin->createUser([
    'username' => 'jane.doe',
    'email' => 'jane@example.com',
    'enabled' => true,
], realmRoles: ['user'], clientRoles: [], password: 'ChangeMe123');

$admin->assignRolesToUser($userId, ['admin']);
$admin->sendVerificationEmail($userId);
```

## 8. Custom user provider (optional)

If you have your own user storage, set user_provider_service in keycloak.yaml to the ID of your service implementing Symfony’s UserProviderInterface. The bundle will alias keycloak.user_provider to your service automatically.

## 9. Translations

The bundle provides messages in:
- translations/messages.en.yaml
- translations/messages.fr.yaml

Ensure the translator is enabled in your framework config if needed.

## 10. Troubleshooting

- Invalid state or missing code_verifier: Make sure sessions are enabled and not reset by proxies; verify that the callback URL domain matches your app domain.
- Invalid or expired token: Check the realm public key (KEYCLOAK_PUBLIC_KEY), algorithm (RS256), and client configuration in Keycloak.
- 401 on API: Verify the Authorization: Bearer <token> header and that the token audience/realm roles match your access rules.

## 11. Useful services and aliases

- keycloak.oidc_service → OIDCService
- keycloak.admin_service → KeycloakAdminService
- keycloak.token_refresh_service → TokenRefreshService
- keycloak.authenticator → KeycloakAuthenticator
- keycloak.jwt_authenticator → JwtAuthenticator
- keycloak.user_provider → KeycloakUserProvider (overridden if user_provider_service is set)

---
License: MIT (see LICENSE)