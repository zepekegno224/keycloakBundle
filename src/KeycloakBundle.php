<?php

namespace Zepekegno\KeycloakBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * KeycloakBundle for Keycloak integration in Symfony
 *
 * This bundle provides services for authentication, registration
 * and user management via Keycloak in a multi-platform
 * architecture with SSO.
 */
class KeycloakBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }
}
