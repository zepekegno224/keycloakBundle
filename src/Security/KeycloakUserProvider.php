<?php

namespace Zepekegno\KeycloakBundle\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class KeycloakUserProvider implements UserProviderInterface
{
    /**
     * Keycloak user provider
     * Handles the creation and refresh of Keycloak users
     */
    /**
     * Loads a user by its identifier
     */
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        // In the Keycloak context, the user is usually created
        // by the authenticator after token validation
        // This provider is mainly used for refresh
        throw new UserNotFoundException(sprintf('User "%s" not found.', $identifier));
    }

    /**
     * Refreshes a user
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof KeycloakUser) {
            throw new UnsupportedUserException(sprintf('User of type "%s" is not supported.', get_class($user)));
        }

        // For Keycloak, return the user as-is
        // Data refresh is done via tokens
        return $user;
    }

    /**
     * Checks if this class supports the given user type
     */
    public function supportsClass(string $class): bool
    {
        return KeycloakUser::class === $class || is_subclass_of($class, KeycloakUser::class);
    }

    /**
     * Deprecated method for compatibility
     * @deprecated since Symfony 5.3, use loadUserByIdentifier() instead
     */
    public function loadUserByUsername(string $username): UserInterface
    {
        return $this->loadUserByIdentifier($username);
    }
}
