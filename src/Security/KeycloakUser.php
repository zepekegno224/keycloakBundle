<?php

namespace Zepekegno\KeycloakBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Represents a Keycloak user in the Symfony security system
 */
class KeycloakUser implements UserInterface
{
    /**
     * @param string $id Keycloak identifier (sub)
     * @param string $username Username
     * @param string $email User email
     * @param array $roles User roles
     * @param array $attributes Additional token attributes
     */
    public function __construct(
        private string $id,
        private string $username,
        private string $email,
        private array $roles = [],
        private array $attributes = []
    ) {
    }

    /**
     * Returns the Keycloak identifier of the user
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Returns the user's email
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * Returns the token attributes
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * Gets a specific attribute
     */
    public function getAttribute(string $name, $default = null)
    {
        return $this->attributes[$name] ?? $default;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // Ensure each user has at least ROLE_USER
        $roles[] = 'ROLE_USER';
        return array_unique($roles);
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
        // Nothing to do as we don't use local passwords
    }

    /**
     * {@inheritdoc}
     */
    public function getUserIdentifier(): string
    {
        return $this->id;
    }
}
