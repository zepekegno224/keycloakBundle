<?php

namespace Zepekegno\KeycloakBundle\Service;

use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;

class OIDCService
{
    /**
     * Service to handle OIDC authentication with Keycloak
     */
    private HttpClientInterface $httpClient;
    private ?Request $request = null;

    public function __construct(
        private string $keycloakBaseUrl,
        private string $keycloakRealm,
        private string $keycloakClientId,
        private string $keycloakClientSecret,
        private string $keycloakPublicKey,
        private string $keycloakAlgorithm,
        private string $keycloakScope,
        private readonly UrlGeneratorInterface $urlGeneratorInterface,
        private bool $keycloakVerifyToken = true,
        private ?RequestStack $requestStack = null
    ) {
        $this->httpClient = HttpClient::create();

        if ($this->requestStack) {
            $this->request = $this->requestStack->getCurrentRequest();
        }
    }

    /**
     * Generates a PKCE code challenge from a code verifier
     *
     * @param string $codeVerifier Code verifier
     * @return string Code challenge
     */
    private function generateCodeChallenge(string $codeVerifier): string
    {
        $hash = hash('sha256', $codeVerifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * Generates a random PKCE code verifier
     *
     * @param int $length Code verifier length
     * @return string Code verifier
     */
    public function generateCodeVerifier(int $length = 64): string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    /**
     * Generates the Keycloak login URL with PKCE
     *
     * @param string $codeVerifier PKCE code verifier
     * @param string $state CSRF state value
     * @param array $additionalParams Additional query parameters
     * @return string Login URL
     */
    public function getLoginUrl(string $codeVerifier, string $state, array $additionalParams = []): string
    {
        $codeChallenge = $this->generateCodeChallenge($codeVerifier);

        $params = array_merge([
            'client_id' => $this->keycloakClientId,
            'redirect_uri' => $this->urlGeneratorInterface->generate(KeycloakConstants::ROUTE_CALLBACK, [], UrlGeneratorInterface::ABSOLUTE_URL),
            'response_type' => 'code',
            'scope' => $this->keycloakScope,
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ], $additionalParams);

        return "{$this->keycloakBaseUrl}/realms/{$this->keycloakRealm}/protocol/openid-connect/auth?" . http_build_query($params);
    }

    /**
     * Generates the SSO login URL with prompt=none
     *
     * @param string $codeVerifier PKCE code verifier
     * @param string $state CSRF state value
     * @return string SSO login URL
     */
    public function getSsoLoginUrl(string $codeVerifier, string $state): string
    {
        return $this->getLoginUrl($codeVerifier, $state, ['prompt' => 'none']);
    }

    /**
     * Exchanges an authorization code for tokens
     *
     * @param string $code Authorization code
     * @param string $codeVerifier PKCE code verifier
     * @return array Tokens (access_token, refresh_token, id_token)
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $response = $this->httpClient->request('POST', "{$this->keycloakBaseUrl}/realms/{$this->keycloakRealm}/protocol/openid-connect/token", [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => [
                'grant_type' => 'authorization_code',
                'client_id' => $this->keycloakClientId,
                'client_secret' => $this->keycloakClientSecret,
                'code' => $code,
                'redirect_uri' => $this->urlGeneratorInterface->generate(KeycloakConstants::ROUTE_CALLBACK, [], UrlGeneratorInterface::ABSOLUTE_URL),
                'code_verifier' => $codeVerifier,
            ],
        ]);

        return json_decode($response->getContent(), true);
    }

    /**
     * Refreshes an access token using a refresh token
     *
     * @param string $refreshToken Refresh token
     * @return array New tokens
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function refreshToken(string $refreshToken): array
    {
        $response = $this->httpClient->request('POST', "{$this->keycloakBaseUrl}/realms/{$this->keycloakRealm}/protocol/openid-connect/token", [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => [
                'grant_type' => 'refresh_token',
                'client_id' => $this->keycloakClientId,
                'client_secret' => $this->keycloakClientSecret,
                'refresh_token' => $refreshToken,
            ],
        ]);

        return json_decode($response->getContent(), true);
    }

    /**
     * Retrieves user information from the userinfo endpoint
     *
     * @param string $accessToken Access token
     * @return array User information
     * @throws ClientExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function getUserInfo(string $accessToken): array
    {
        $response = $this->httpClient->request('GET', "{$this->keycloakBaseUrl}/realms/{$this->keycloakRealm}/protocol/openid-connect/userinfo", [
            'headers' => [
                'Authorization' => "Bearer {$accessToken}",
            ],
        ]);

        return json_decode($response->getContent(), true);
    }

    /**
     * Validates a JWT token
     *
     * @param string $token JWT to validate
     * @return array|null Token payload if valid, null otherwise
     */
    public function validateToken(string $token): ?array
    {
        if (!$this->keycloakVerifyToken) {
            // Decoding without verification (not recommended in production)
            $tokenParts = explode('.', $token);
            if (count($tokenParts) !== 3) {
                return null;
            }
            return json_decode(base64_decode(strtr($tokenParts[1], '-_', '+/')), true);
        }

        try {
            // Format public key
            $publicKey = "-----BEGIN PUBLIC KEY-----\n{$this->keycloakPublicKey}\n-----END PUBLIC KEY-----";

            // Verify and decode token
            $decoded = JWT::decode($token, new Key(trim($publicKey), $this->keycloakAlgorithm));

            // Convert object to array
            return json_decode(json_encode($decoded), true);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Performs Keycloak logout using the refresh token
     *
     * @param string $refreshToken Refresh token
     * @return bool True if logout succeeded, false otherwise
     */
    public function logout(string $refreshToken): bool
    {
       $response = $this->httpClient->request('POST', sprintf('%s/realms/%s/protocol/openid-connect/logout',
			$this->keycloakBaseUrl, $this->keycloakRealm
		), [
			'body' => [
				'client_id' => $this->keycloakClientId,
				'client_secret' => $this->keycloakClientSecret,
				'refresh_token' => $refreshToken,
			]
		]);
        return $response->getStatusCode() === 204;
    }

    /**
     * Extracts the Bearer token from the request
     *
     * @param Request|null $request HTTP request (uses current request if null)
     * @return string|null Bearer token or null if not found
     */
    public function extractBearerToken(?Request $request = null): ?string
    {
        $request = $request ?? $this->request;
        if (!$request) {
            return null;
        }

        $authHeader = $request->headers->get('Authorization');
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }

        return substr($authHeader, 7);
    }

    /**
     * Decodes a JWT token without signature verification (useful for tests)
     */
    public function decodeTokenWithoutVerification(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new \InvalidArgumentException('Token JWT invalide');
        }

        $payload = base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[1]));
        $data = json_decode($payload, true);

        if (!$data) {
            throw new \InvalidArgumentException('Impossible de décoder le payload du token');
        }

        return $data;
    }
}
