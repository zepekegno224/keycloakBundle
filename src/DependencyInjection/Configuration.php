<?php

namespace Zepekegno\KeycloakBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Keycloak bundle configuration
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('keycloak');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->scalarNode('base_url')
                    ->info('Keycloak server base URL')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('realm')
                    ->info('Keycloak realm name')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('client_id')
                    ->info('Public client ID for OIDC')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('client_secret')
                    ->info('Client secret for OIDC')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('admin_client_id')
                    ->info('Admin client ID for administration API')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('admin_client_secret')
                    ->info('Admin client secret for administration API')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('public_key')
                    ->info('Clé publique du realm pour vérifier les JWT')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->booleanNode('verify_token')
                    ->info('Activer la vérification des tokens JWT')
                    ->defaultTrue()
                ->end()
                ->scalarNode('algorithm')
                    ->info('Algorithme de signature utilisé pour les JWT')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('user_provider_service')
                    ->info('Service de fournisseur d\'utilisateurs Symfony')
                    ->defaultNull()
                ->end()
                ->arrayNode('redirect_routes')
                    ->info('Routes de redirection en fonction des rôles')
                    ->useAttributeAsKey('role')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
                ->scalarNode('scope')
                    ->info('Scope OIDC')
                    ->defaultValue('openid profile email')
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
