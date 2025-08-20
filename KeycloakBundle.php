<?php

namespace Zepekegno\KeycloakBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * KeycloakBundle pour l'intégration de Keycloak dans Symfony
 *
 * Ce bundle fournit des services pour l'authentification, l'inscription
 * et la gestion des utilisateurs via Keycloak dans une architecture
 * multi-plateformes avec SSO.
 */
class KeycloakBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }
}
