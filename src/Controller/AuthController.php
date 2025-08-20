<?php

namespace Zepekegno\KeycloakBundle\Controller;

use Zepekegno\KeycloakBundle\Service\KeycloakAdminService;
use Zepekegno\KeycloakBundle\Service\OIDCService;
use Zepekegno\KeycloakBundle\Service\TokenRefreshService;
use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class AuthController extends AbstractController
{
    /**
     * Controller to handle Keycloak authentication
     */
    public function __construct(
        private KeycloakAdminService $keycloakAdminService,
        private OIDCService $oidcService,
        private TokenStorageInterface $tokenStorage,
        private TokenRefreshService $tokenRefreshService
    ) {
    }

    /**
     * Redirects to the Keycloak login page
     */
    #[Route('/login', name: KeycloakConstants::ROUTE_LOGIN, methods: ['GET'])]
    public function login(Request $request, SessionInterface $session): RedirectResponse
    {
        // Generate PKCE code verifier and CSRF state
        $codeVerifier = $this->oidcService->generateCodeVerifier();
        $state = bin2hex(random_bytes(16));

        // Store code verifier and state in session
        $session->set(KeycloakConstants::SESSION_CODE_VERIFIER, $codeVerifier);
        $session->set(KeycloakConstants::SESSION_STATE, $state);

        // Check if this is an SSO attempt
        $sso = $request->query->getBoolean('sso', false);

        // Generate login URL
        $loginUrl = $sso ? $this->oidcService->getSsoLoginUrl($codeVerifier, $state) : $this->oidcService->getLoginUrl($codeVerifier, $state);

        return new RedirectResponse($loginUrl);
    }

    /**
     * Keycloak callback - entry point for the authenticator
     */
    #[Route('/callback', name: KeycloakConstants::ROUTE_CALLBACK, methods: ['GET'])]
    public function callback(Request $request): Response
    {
        // This method serves only as an entry point for Keycloak
        // The authenticator handles all authentication logic
        // Redirect to default profile
        return $this->redirectToRoute(KeycloakConstants::ROUTE_PROFILE);
    }

    /**
     * Displays the user's profile information
     */
    #[Route('/profile', name: KeycloakConstants::ROUTE_PROFILE, methods: ['GET'])]
    public function profile(SessionInterface $session): Response
    {
        // Check if user is authenticated
        $accessToken = $session->get(KeycloakConstants::SESSION_ACCESS_TOKEN);
        if (!$accessToken) {
            return $this->redirectToRoute(KeycloakConstants::ROUTE_LOGIN);
        }

        try {
            // Get user information
            $userInfo = $this->oidcService->getUserInfo($accessToken);
            return $this->json($userInfo);
        } catch (\Exception $e) {
            // If token is expired, try to refresh it
            $refreshResult = $this->tokenRefreshService->refreshToken($session);

            if ($refreshResult->isSuccess()) {
                // Token refreshed successfully, retry
                try {
                    $newAccessToken = $session->get(KeycloakConstants::SESSION_ACCESS_TOKEN);
                    $userInfo = $this->oidcService->getUserInfo($newAccessToken);
                    return $this->json($userInfo);
                } catch (\Exception $retryException) {
                    // Even with new token, it doesn't work
                    $this->tokenRefreshService->clearKeycloakSession($session, 'userinfo_failed_after_refresh');
                    return $this->redirectToRoute(KeycloakConstants::ROUTE_LOGIN);
                }
            }

            // Refresh failed
            if ($refreshResult->shouldClearSession()) {
                $this->tokenRefreshService->clearKeycloakSession($session, 'userinfo_failed_no_refresh');
            }

            return $this->redirectToRoute(KeycloakConstants::ROUTE_LOGIN);
        }
    }

    /**
     * Logs out the user
     */
    #[Route('/logout', name: KeycloakConstants::ROUTE_LOGOUT, methods: ['GET', 'POST'])]
    public function logout(Request $request, SessionInterface $session): Response
    {

        $refreshToken = $session->get(name: KeycloakConstants::SESSION_REFRESH_TOKEN);
        $session->invalidate();

        // Generate Keycloak logout URL
        if ($refreshToken) {
            $this->oidcService->logout($refreshToken);
        }

        // If logout failed, redirect to login page
        return $this->redirectToRoute(KeycloakConstants::ROUTE_LOGIN);
    }
}
