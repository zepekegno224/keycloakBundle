# Token Refresh

The bundle provides automatic token refresh capabilities and a service to refresh tokens manually.

## 1) Automatic refresh

The TokenExpirationListener checks token expiration on each request and attempts a refresh when possible.

- Listener: Zepekegno\KeycloakBundle\EventListener\TokenExpirationListener
- Service: keycloak.token_refresh_service → TokenRefreshService

The listener is enabled via a kernel.event_subscriber tag in the bundle’s services (see services.yaml). No additional setup is required.

## 2) Manual refresh

Use the TokenRefreshService to refresh tokens explicitly:

```php
<?php

use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Zepekegno\KeycloakBundle\Service\TokenRefreshService;

/** @var TokenRefreshService $refresh */
$refresh = $this->container->get('keycloak.token_refresh_service');

// Example: refresh using the refresh token you stored in session
$tokens = $refresh->refreshTokens($session->get('keycloak_refresh_token'));

// Or with retry logic
$tokens = $refresh->refreshTokensWithRetry($session->get('keycloak_refresh_token'), 2);

// Update session with new tokens
$refresh->updateSessionTokens($session, $tokens);
```

## 3) Troubleshooting refresh

- Ensure the refresh token is still valid (Keycloak may rotate/expire it).
- Check KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET match the client used to obtain tokens.
- Verify time drift between app and Keycloak servers (NTP).