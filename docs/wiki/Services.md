# Services

This page lists the main services and aliases provided by the bundle.
For exact definitions, see: ../../config/services.yaml

## Aliases

- keycloak.admin_service → Zepekegno\KeycloakBundle\Service\KeycloakAdminService
- keycloak.oidc_service → Zepekegno\KeycloakBundle\Service\OIDCService
- keycloak.token_refresh_service → Zepekegno\KeycloakBundle\Service\TokenRefreshService
- keycloak.authenticator → Zepekegno\KeycloakBundle\Security\KeycloakAuthenticator
- keycloak.authenticator_entrypoint → Zepekegno\KeycloakBundle\Security\KeycloakAuthenticatorEntrypoint
- keycloak.jwt_authenticator → Zepekegno\KeycloakBundle\Security\KeycloakJwtAuthenticator
- keycloak.jwt_authenticator_entrypoint → Zepekegno\KeycloakBundle\Security\KeycloakJwtAuthenticatorEntrypoint
- keycloak.user_provider → Zepekegno\KeycloakBundle\Security\KeycloakUserProvider

## Notable concrete services

- Zepekegno\KeycloakBundle\Controller\AuthController
- Zepekegno\KeycloakBundle\EventListener\TokenExpirationListener
- Zepekegno\KeycloakBundle\EventListener\AuthenticationSuccessListener
- Zepekegno\KeycloakBundle\Service\TokenRefreshService
- Zepekegno\KeycloakBundle\Service\KeycloakAdminService
- Zepekegno\KeycloakBundle\Service\OIDCService
- Zepekegno\KeycloakBundle\Security\KeycloakAuthenticator
- Zepekegno\KeycloakBundle\Security\KeycloakJwtAuthenticator
- Zepekegno\KeycloakBundle\Security\KeycloakAuthenticatorEntrypoint
- Zepekegno\KeycloakBundle\Security\KeycloakJwtAuthenticatorEntrypoint
- Zepekegno\KeycloakBundle\Security\KeycloakUserProvider