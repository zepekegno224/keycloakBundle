<?php

namespace Zepekegno\KeycloakBundle\EventListener;

use Zepekegno\KeycloakBundle\Service\TokenRefreshService;
use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class TokenExpirationListener implements EventSubscriberInterface
{
    /**
     * Listener that checks Keycloak token expiration on each request
     * and attempts to refresh them automatically
     */
    private const EXCLUDED_ROUTES = [
        KeycloakConstants::ROUTE_LOGIN,
        KeycloakConstants::ROUTE_CALLBACK,
        KeycloakConstants::ROUTE_LOGOUT,
        KeycloakConstants::ROUTE_REGISTER
    ];

    public function __construct(
        private TokenRefreshService $tokenRefreshService,
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 10], // High priority to check before authentication
        ];
    }

    /**
     * Checks JWT token validity on each request
     */
    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $session = $request->getSession();

        // Ignore excluded routes
        $currentRoute = $request->attributes->get('_route');
        if (in_array($currentRoute, self::EXCLUDED_ROUTES)) {
            return;
        }

        // Check if user has a token in session
        $accessToken = $session->get(KeycloakConstants::SESSION_ACCESS_TOKEN);
        if (!$accessToken) {
            return;
        }

        // Check if token is expired
        if ($this->isTokenExpired($session)) {
            $this->handleExpiredToken($session, $event);
        }
    }

    /**
     * Checks if token is expired
     */
    private function isTokenExpired(SessionInterface $session): bool
    {
        return $this->tokenRefreshService->isTokenExpired($session);
    }

    /**
     * Handles expired token by trying to refresh it or logging out the user
     */
    private function handleExpiredToken(SessionInterface $session, RequestEvent $event): void
    {
        $refreshResult = $this->tokenRefreshService->refreshToken($session);

        if ($refreshResult->isSuccess()) {
            // Token refreshed successfully, continue request
            return;
        }

        // Refresh failed
        if ($refreshResult->shouldClearSession()) {
            $this->tokenRefreshService->clearKeycloakSession($session, 'refresh_failed');
        }

        // Redirect to the login page
        $loginUrl = $this->urlGenerator->generate(KeycloakConstants::ROUTE_LOGIN);
        $event->setResponse(new RedirectResponse($loginUrl));
    }
}
