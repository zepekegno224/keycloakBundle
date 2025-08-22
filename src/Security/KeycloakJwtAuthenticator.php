<?php

namespace Zepekegno\KeycloakBundle\Security;

use Zepekegno\KeycloakBundle\Service\OIDCService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\Translation\TranslatorInterface;

class KeycloakJwtAuthenticator extends AbstractAuthenticator
{
    /**
     * JWT authenticator for Keycloak
     */
    public function __construct(
        private OIDCService $oidcService,
        private TranslatorInterface $translator,
        private ?UserProviderInterface $userProviderService = null
    ) {
    }

    /**
     * Checks whether this authenticator supports the request
     */
    public function supports(Request $request): bool
    {
        return $this->oidcService->extractBearerToken($request) !== null;
    }

    /**
     * Authenticates the user from the JWT
     */
    public function authenticate(Request $request): Passport
    {
        $token = $this->oidcService->extractBearerToken($request);
        if (!$token) {
            throw new CustomUserMessageAuthenticationException('keycloak.jwt.missing_token');
        }

        $tokenData = $this->oidcService->validateToken($token);
        if (!$tokenData) {
            throw new CustomUserMessageAuthenticationException('keycloak.jwt.invalid');
        }

        // Check token expiration
        if (isset($tokenData['exp']) && $tokenData['exp'] < time()) {
            throw new CustomUserMessageAuthenticationException('keycloak.jwt.expired');
        }

        // Check user identifier
        if (!isset($tokenData['sub'])) {
            throw new CustomUserMessageAuthenticationException('keycloak.jwt.invalid_missing_user');
        }

        // Create user badge with Keycloak identifier
        return new SelfValidatingPassport(
            new UserBadge($tokenData['sub'], function ($userIdentifier) use ($tokenData) {
                // If a user provider service is configured, use it
                if ($this->userProviderService) {
                    return $this->userProviderService->loadUserByIdentifier($userIdentifier);
                }

                // Otherwise, create a basic Keycloak user
                // Extract realm roles
                $realmRoles = $tokenData['realm_access']['roles'] ?? [];

                // Extract client roles
                $clientRoles = [];
                if (isset($tokenData['resource_access']) && is_array($tokenData['resource_access'])) {
                    foreach ($tokenData['resource_access'] as $clientId => $access) {
                        if (isset($access['roles']) && is_array($access['roles'])) {
                            foreach ($access['roles'] as $role) {
                                $clientRoles[] =  $role;
                            }
                        }
                    }
                }

                // Combine realm and client roles
                $allRoles = array_merge($realmRoles, $clientRoles);

                return new KeycloakUser(
                    $userIdentifier,
                    $tokenData['preferred_username'] ?? '',
                    $tokenData['email'] ?? '',
                    $allRoles,
                    $tokenData
                );
            })
        );
    }

    /**
     * Called on successful authentication
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // Authentication successful, let request continue
        return null;
    }

    /**
     * Called on authentication failure
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $message = $exception instanceof CustomUserMessageAuthenticationException
            ? $this->translator->trans($exception->getMessageKey(), $exception->getMessageData())
            : $exception->getMessage();

        return new JsonResponse(
            ['error' => $message],
            Response::HTTP_UNAUTHORIZED
        );
    }
}
