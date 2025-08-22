<?php

namespace Zepekegno\KeycloakBundle\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

class AuthenticationSuccessListener implements EventSubscriberInterface
{
    private const FIRWALL_CONTEXT = "_firewall_context";
    /**
     * EventListener that manages redirection after a Keycloak authentication
     */
    public function __construct(
        private UrlGeneratorInterface $urlGenerator,
        private array $keycloakRoutes
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
        ];
    }

    /**
     * Handles redirection after a successful authentication
     */
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        $request = $event->getRequest();
        $session = $request->getSession();
        $firewallContext = explode('.', $request->attributes->get(self::FIRWALL_CONTEXT));
        $targetPath = sprintf('_security.%s.target_path', end($firewallContext));
        if ($session->has($targetPath)) {
            $targetUrl = $session->get($targetPath);
            $response = new RedirectResponse($targetUrl);
            $event->setResponse($response);
            return;
        }

        // Role-based redirection
        $roles = $user->getRoles();

        foreach ($roles as $role) {
            if (isset($this->keycloakRoutes[$role])) {
                $redirectUrl = $this->keycloakRoutes[$role];
                // If it's a route name, generate the URL
                if (!str_starts_with($redirectUrl, '/') && !str_starts_with($redirectUrl, 'http')) {
                    $redirectUrl = $this->urlGenerator->generate($redirectUrl);
                }

                $response = new RedirectResponse($redirectUrl);
                $event->setResponse($response);
                return;
            }
        }

        // Default redirection
        $defaultRedirect = $this->keycloakRoutes['default'] ?? '/auth/profile';

        // If it's a route name, generate the URL
        if (!str_starts_with($defaultRedirect, '/') && !str_starts_with($defaultRedirect, 'http') && !str_starts_with($defaultRedirect, 'https')) {
            $defaultRedirect = $this->urlGenerator->generate($defaultRedirect);
        }

        $response = new RedirectResponse($defaultRedirect);
        $event->setResponse($response);
    }
}
