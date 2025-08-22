<?php

namespace Zepekegno\KeycloakBundle\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;

class KeycloakAuthenticatorEntrypoint implements AuthenticationEntryPointInterface
{
    public function __construct(
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function start(Request $request, ?AuthenticationException $authException = null): RedirectResponse
    {

        return new RedirectResponse($this->urlGenerator->generate(KeycloakConstants::ROUTE_LOGIN));
    }
}
