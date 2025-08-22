<?php

namespace Zepekegno\KeycloakBundle\Security;

use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;
use Zepekegno\KeycloakBundle\Service\OIDCService;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class KeycloakAuthenticator extends AbstractAuthenticator
{
    use TargetPathTrait;

    public function __construct(
        private OIDCService $oidcService,
        private UrlGeneratorInterface $urlGenerator,
        private ?UserProviderInterface $keycloakUserProviderService = null,
        private string $callbackRoute = KeycloakConstants::ROUTE_CALLBACK,
        private string $firewallName = 'main'
    ) {}

    public function supports(Request $request): ?bool
    {
        // Support only callback route with a code
        return $request->attributes->get('_route') === $this->callbackRoute && $request->query->has('code');
    }

    public function authenticate(Request $request): Passport
    {
        $session = $request->getSession();

        $code = $request->query->get('code');
        $state = $request->query->get('state');
        $error = $request->query->get('error');
        $errorDescription = $request->query->get('error_description');

        // Error handling
        if ($error) {
            throw new CustomUserMessageAuthenticationException('keycloak.auth.keycloak_error', [
                '%error%' => $error,
                '%description%' => (string) $errorDescription,
            ]);
        }

        if (!$code || !$state) {
            throw new CustomUserMessageAuthenticationException('keycloak.auth.missing_params');
        }

        // State verification (anti CSRF)
        $sessionState = $session->get(KeycloakConstants::SESSION_STATE);
        if (!$sessionState || $state !== $sessionState) {
            throw new CustomUserMessageAuthenticationException('keycloak.auth.invalid_state');
        }

        // Get code verifier for PKCE
        $codeVerifier = $session->get(KeycloakConstants::SESSION_CODE_VERIFIER);
        if (!$codeVerifier) {
            throw new CustomUserMessageAuthenticationException('keycloak.auth.missing_code_verifier');
        }

        // Exchange code for tokens
        try {
            $tokens = $this->oidcService->exchangeCode($code, $codeVerifier);
        } catch (\Exception $e) {
            throw new CustomUserMessageAuthenticationException('keycloak.auth.code_exchange_error', [
                '%message%' => $e->getMessage(),
            ]);
        }

        // Store tokens in session if needed
        $session->set(KeycloakConstants::SESSION_ACCESS_TOKEN, $tokens['access_token']);
        $session->set(KeycloakConstants::SESSION_REFRESH_TOKEN, $tokens['refresh_token'] ?? null);
        $session->set(KeycloakConstants::SESSION_ID_TOKEN, $tokens['id_token']);
        $session->set(KeycloakConstants::SESSION_TOKEN_EXPIRATION, time() + ($tokens['expires_in'] ?? 3600));

        // Validate token and get user info
        $tokenData = $this->oidcService->validateToken($tokens['access_token']);
        if (!$tokenData) {
            throw new CustomUserMessageAuthenticationException('Token invalide.');
        }

        // Store user data in session
        $session->set(KeycloakConstants::SESSION_USER_DATA, $tokenData);

        // Extract roles
        $realmRoles = $tokenData['realm_access']['roles'] ?? [];
        $clientRoles = [];
        if (isset($tokenData['resource_access']) && is_array($tokenData['resource_access'])) {
            foreach ($tokenData['resource_access'] as $clientId => $access) {
                if (isset($access['roles']) && is_array($access['roles'])) {
                    foreach ($access['roles'] as $role) {
                        $clientRoles[] = $role;
                    }
                }
            }
        }
        $allRoles = array_merge($realmRoles, $clientRoles);

        // Create Keycloak user
        $user = new KeycloakUser(
            $tokenData['sub'],
            $tokenData['preferred_username'] ?? '',
            $tokenData['email'] ?? '',
            $allRoles,
            $tokenData
        );

        return new SelfValidatingPassport(
            new UserBadge($user->getUserIdentifier(), function () use ($user) {
                if ($this->keycloakUserProviderService !== null) {
                    return $this->keycloakUserProviderService->loadUserByIdentifier($user->getUserIdentifier());
                }
                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $session = $request->getSession();

        // Generate state and code verifier
        $codeVerifier = $this->oidcService->generateCodeVerifier();
        $state = bin2hex(random_bytes(16));
        $session->set(KeycloakConstants::SESSION_CODE_VERIFIER, $codeVerifier);
        $session->set(KeycloakConstants::SESSION_STATE, $state);

        // Keycloak login URL with PKCE + state
        $loginUrl = $this->oidcService->getLoginUrl($codeVerifier, $state);

        return new RedirectResponse($loginUrl);
    }
}
