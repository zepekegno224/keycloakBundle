# FAQ

Q: How can I redirect users based on their roles after login?
A: Use keycloak.redirect_routes in the configuration, e.g., ROLE_ADMIN -> admin_dashboard, ROLE_USER -> app_home. An authentication success listener will use this map to redirect.

Q: Can I plug in my own UserProvider?
A: Yes. Set keycloak.user_provider_service to your UserProvider service ID. The bundle will use it to load the user (Web and API).

Q: How do I enable silent SSO authentication?
A: Call /login?sso=1 to use prompt=none on the authorization request.

Q: Can I validate a token without signature verification (dev only)?
A: Set keycloak.verify_token to false. In production, keep it true to validate signature and claims.

Q: How can I refresh tokens automatically on the Web side?
A: Use TokenRefreshService::refreshTokenIfNeeded before critical actions and/or add a periodic refresh mechanism via a listener or app middleware.

Q: How do I assign client roles to a user via the Admin API?
A: Use KeycloakAdminService::assignClientRolesToUser($userId, ['ROLE_X', ...]) after creating the user. The service resolves the client UUID and assigns roles.