<?php

namespace Zepekegno\KeycloakBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * Extension to load Keycloak bundle configuration
 */
class KeycloakExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../../config'));
        $loader->load('services.yaml');

        // Define configuration parameters for services
        $container->setParameter('keycloak.base_url', $config['base_url']);
        $container->setParameter('keycloak.realm', $config['realm']);
        $container->setParameter('keycloak.client_id', $config['client_id']);
        $container->setParameter('keycloak.client_secret', $config['client_secret']);
        $container->setParameter('keycloak.admin_client_id', $config['admin_client_id']);
        $container->setParameter('keycloak.admin_client_secret', $config['admin_client_secret']);
        $container->setParameter('keycloak.public_key', $config['public_key']);
        $container->setParameter('keycloak.verify_token', $config['verify_token']);
        $container->setParameter('keycloak.user_provider_service', $config['user_provider_service']);
        $container->setParameter('keycloak.redirect_routes', $config['redirect_routes']);
        $container->setParameter('keycloak.algorithm', $config['algorithm']);
        $container->setParameter('keycloak.scope', $config['scope']);

        // Define route parameters using constants
        $container->setParameter('keycloak.route.callback', \Zepekegno\KeycloakBundle\Constants\KeycloakConstants::ROUTE_CALLBACK);
        $container->setParameter('keycloak.route.login', \Zepekegno\KeycloakBundle\Constants\KeycloakConstants::ROUTE_LOGIN);
        $container->setParameter('keycloak.route.logout', \Zepekegno\KeycloakBundle\Constants\KeycloakConstants::ROUTE_LOGOUT);
        $container->setParameter('keycloak.route.profile', \Zepekegno\KeycloakBundle\Constants\KeycloakConstants::ROUTE_PROFILE);
        $container->setParameter('keycloak.route.register', \Zepekegno\KeycloakBundle\Constants\KeycloakConstants::ROUTE_REGISTER);

        // Configure user provider according to configuration
        $this->configureUserProvider($container, $config);
    }

    /**
     * Configure user provider according to configuration
     */
    private function configureUserProvider(ContainerBuilder $container, array $config): void
    {
        if (!empty($config['user_provider_service'])) {
            // If a custom service is configured, create an alias to this service
            $container->setAlias('keycloak.user_provider', $config['user_provider_service'])
                ->setPublic(true);
        }
        // Otherwise, the default alias to KeycloakUserProvider remains in place (defined in services.yaml)
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias(): string
    {
        return 'keycloak';
    }
}
