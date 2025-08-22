# Troubleshooting

## HTML or 302 on API routes

Symptom: Calling /api returns an HTML page or a 302 redirect.

Fix:
- Use the JWT API entrypoint to ensure 401 JSON when unauthenticated.
- Ensure your API firewall is stateless.

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

## Infinite login redirects on web routes

Symptoms:
- Repeated redirects between your app and Keycloak.
- You never land on the target page.

Fix:
- Ensure PUBLIC_ACCESS for the bundle routes (login/callback/logout/profile).
- Verify sessions are enabled and not being dropped by proxies.
- Confirm your callback URL host matches your application host.

```yaml
access_control:
  - { path: ^/keycloak/(login|callback|logout|profile), roles: PUBLIC_ACCESS }
```

## “Invalid state” or missing PKCE data

Symptoms:
- Exception about invalid state or missing code_verifier.

Fix:
- Check session configuration; ensure cookies are sent and not stripped.
- Ensure HTTPS and proper cookie settings in production.
- Verify you do not accidentally reset the session between login and callback.

## Token refresh not happening

Symptoms:
- 401 after some time; tokens not refreshed.

Fix:
- The TokenExpirationListener is enabled by default via event subscriber.
- Check that refresh tokens are present and valid in the session.
- Review system clock synchronization (NTP) to avoid premature expiry.

## Invalid token signature

Symptoms:
- “Invalid signature” or similar verification error.

Fix:
- Check KEYCLOAK_PUBLIC_KEY and algorithm in configuration (RS256 typical).
- Ensure the realm and client configuration match the issued tokens.