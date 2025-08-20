<?php

namespace Zepekegno\KeycloakBundle\Service;

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;

/**
 * Service to interact with Keycloak Admin API
 */
class KeycloakAdminService
{
    private HttpClientInterface $httpClient;
    private ?string $adminToken = null;
    private ?int $tokenExpiration = null;

    public function __construct(
        private string $keycloakBaseUrl,
        private string $keycloakRealm,
        private string $keycloakClientId,
        private string $keycloakAdminClientId,
        private string $keycloakAdminClientSecret
    ) {
        $this->httpClient = HttpClient::create();
    }

    /**
     * Gets an access token for the Admin API
     *
     * @return string The access token
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function getAdminToken(): string
    {
        // Check if token is still valid
        if ($this->adminToken && $this->tokenExpiration > time()) {
            return $this->adminToken;
        }

        // Get a new token
        $response = $this->httpClient->request('POST', "{$this->keycloakBaseUrl}/realms/{$this->keycloakRealm}/protocol/openid-connect/token", [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => [
                'grant_type' => 'client_credentials',
                'client_id' => $this->keycloakAdminClientId,
                'client_secret' => $this->keycloakAdminClientSecret,
            ],
        ]);

        $data = json_decode($response->getContent(), true);
        $this->adminToken = $data['access_token'];
        $this->tokenExpiration = time() + $data['expires_in'] - 60; // 60 seconds safety margin

        return $this->adminToken;
    }

    /**
     * Creates a new user in Keycloak
     *
     * @param array $data User data
     * @param array $realmRoles Realm roles to assign
     * @param array $clientRoles Client roles to assign
     * @param string $password User password
     * @param array $attributes Additional attributes
     * @param array $requiredActions Required actions (default: email verification)
     * @return string Created user ID
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function createUser(
       array $data,
        array $realmRoles,
        array $clientRoles,
        string $password,
        array $attributes = [],
        array $requiredActions = ['VERIFY_EMAIL']
    ): string {
        $token = $this->getAdminToken();

        // Prepare user data
        $userData = [
            'enabled' => true,
            'emailVerified' => false,
            'requiredActions' => $requiredActions,
            'attributes' => $attributes,
            'credentials' => [
                [
                    'type' => 'password',
                    'value' => $password,
                    'temporary' => false
                ]
            ]
        ];

        // Create user
        $response = $this->httpClient->request('POST', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/users", [
            'headers' => [
                'Authorization' => "Bearer {$token}",
                'Content-Type' => 'application/json',
            ],
            'json' => array_merge($userData, $data),
        ]);

        // Get created user ID
        $location = $response->getHeaders()['location'][0];
        $userId = substr($location, strrpos($location, '/') + 1);

        // Assign default realm roles if configured
        if (!empty($this->keycloakDefaultRoles)) {
            $this->assignRolesToUser($userId, $realmRoles);
        }

        // Assign default client roles if configured
        if (!empty($this->keycloakDefaultClientRoles)) {
            foreach ($clientRoles as $roles) {
                if (!empty($roles)) {
                    $this->assignClientRolesToUser($userId, $roles);
                }
            }
        }

        return $userId;
    }

    /**
     * Assigns realm roles to a user
     *
     * @param string $userId User ID
     * @param array $roles List of realm roles to assign
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function assignRolesToUser(string $userId, array $roles): void
    {
        $token = $this->getAdminToken();

        // Get all available roles
        $response = $this->httpClient->request('GET', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/roles", [
            'headers' => [
                'Authorization' => "Bearer {$token}",
            ],
        ]);

        $availableRoles = json_decode($response->getContent(), true);
        $rolesToAssign = [];

        // Filter available roles
        foreach ($availableRoles as $role) {
            if (in_array($role['name'], $roles)) {
                $rolesToAssign[] = [
                    'id' => $role['id'],
                    'name' => $role['name'],
                ];
            }
        }

        // Assign roles to user
        if (!empty($rolesToAssign)) {
            $this->httpClient->request('POST', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/users/{$userId}/role-mappings/realm", [
                'headers' => [
                    'Authorization' => "Bearer {$token}",
                    'Content-Type' => 'application/json',
                ],
                'json' => $rolesToAssign,
            ]);
        }
    }

    /**
     * Assigns client roles to a user
     *
     * @param string $userId User ID
     * @param array $roles List of client roles to assign
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */public function assignClientRolesToUser(string $userId, array $roles): void
{
    $token = $this->getAdminToken();

    // Get internal client ID by clientId filter
    $response = $this->httpClient->request('GET', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/clients", [
        'headers' => [
            'Authorization' => "Bearer {$token}",
            'Accept' => 'application/json',
        ],
        'query' => [
            'clientId' => $this->keycloakClientId,  // pay attention to exact case
        ],
    ]);

    if ($response->getStatusCode() !== 200) {
        throw new \RuntimeException("Error retrieving client {$this->keycloakClientId}: " . $response->getContent(false));
    }

    $clients = $response->toArray();
    if (empty($clients)) {
        throw new \InvalidArgumentException("Client '{$this->keycloakClientId}' not found in realm '{$this->keycloakRealm}'");
    }

    $clientUuid = $clients[0]['id'];

    // Get client roles
    $response = $this->httpClient->request('GET', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/clients/{$clientUuid}/roles", [
        'headers' => [
            'Authorization' => "Bearer {$token}",
            'Accept' => 'application/json',
        ],
    ]);

    if ($response->getStatusCode() !== 200) {
        throw new \RuntimeException("Error retrieving roles for client {$this->keycloakClientId}: " . $response->getContent(false));
    }

    $availableRoles = $response->toArray();

    // Filter requested roles among available roles
    $rolesToAssign = array_filter($availableRoles, fn($role) => in_array($role['name'], $roles, true));

    if (empty($rolesToAssign)) {
        // Nothing to assign, exit
        return;
    }

    // Assign client roles to user
    $response = $this->httpClient->request('POST', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/users/{$userId}/role-mappings/clients/{$clientUuid}", [
        'headers' => [
            'Authorization' => "Bearer {$token}",
            'Content-Type' => 'application/json',
        ],
        'json' => $rolesToAssign,
    ]);

    if (!in_array($response->getStatusCode(), [204, 201], true)) {
        throw new \RuntimeException("Error assigning roles: " . $response->getContent(false));
    }
}


    /**
     * Sends a verification email to the user
     *
     * @param string $userId User ID
     * @param array $actions Actions to execute (default: email verification)
     * @param int $lifespan Link validity duration in seconds (default: 43200 = 12 hours)
     * @param string|null $redirectUri Redirect URI after verification
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function sendVerificationEmail(
        string $userId,
        array $actions = ['VERIFY_EMAIL'],
        int $lifespan = 43200,
        ?string $redirectUri = null
    ): void {
        $token = $this->getAdminToken();

        $queryParams = ['lifespan' => $lifespan];
        if ($redirectUri) {
            $queryParams['redirect_uri'] = $redirectUri;
        }

        $this->httpClient->request('PUT', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/users/{$userId}/send-verify-email", [
            'headers' => [
                'Authorization' => "Bearer {$token}",
                'Content-Type' => 'application/json',
            ],
            'query' => $queryParams,
            'json' => $actions,
        ]);
    }

    /**
     * Retrieves user information
     *
     * @param string $userId User ID
     * @return array User information
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function getUser(string $userId): array
    {
        $token = $this->getAdminToken();

        $response = $this->httpClient->request('GET', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/users/{$userId}", [
            'headers' => [
                'Authorization' => "Bearer {$token}",
            ],
        ]);

        return json_decode($response->getContent(), true);
    }

    /**
     * Searches for users by email
     *
     * @param string $email Email to search for
     * @return array List of matching users
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function findUserByEmail(string $email): array
    {
        $token = $this->getAdminToken();

        $response = $this->httpClient->request('GET', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/users", [
            'headers' => [
                'Authorization' => "Bearer {$token}",
            ],
            'query' => [
                'email' => $email,
                'exact' => true,
            ],
        ]);

    if ($response->getStatusCode() !== 200) {
        throw new \RuntimeException(sprintf(
            'Keycloak API error [%d]: %s',
            $response->getStatusCode(),
            $response->getContent(false)
        ));
    }

    return $response->toArray();

    }

    /**
     * Updates user attributes
     *
     * @param string $userId User ID
     * @param array $attributes Attributes to update
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function updateUserAttributes(string $userId, array $attributes): void
    {
        $token = $this->getAdminToken();

        // Get current user information
        $user = $this->getUser($userId);

        // Merge existing attributes with new ones
        $user['attributes'] = array_merge($user['attributes'] ?? [], $attributes);

        // Update user
        $this->httpClient->request('PUT', "{$this->keycloakBaseUrl}/admin/realms/{$this->keycloakRealm}/users/{$userId}", [
            'headers' => [
                'Authorization' => "Bearer {$token}",
                'Content-Type' => 'application/json',
            ],
            'json' => $user,
        ]);
    }
}
