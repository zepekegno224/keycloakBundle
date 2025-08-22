<?php

namespace Zepekegno\KeycloakBundle\Service;

use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;

/**
 * Service dedicated to Keycloak refresh token management
 *
 * This service centralizes all token renewal logic
 * and provides a simple interface for other components.
 */
class TokenRefreshService
{
    public function __construct(
        private OIDCService $oidcService,
        private ?LoggerInterface $logger = null
    ) {
    }

    /**
     * Checks if a token is near expiration
     *
     * @param SessionInterface $session
     * @param int $marginSeconds Margin in seconds before expiration (default: 60s)
     * @return bool
     */
    public function isTokenNearExpiration(SessionInterface $session, int $marginSeconds = 60): bool
    {
        $tokenExpiration = $session->get(KeycloakConstants::SESSION_TOKEN_EXPIRATION);

        if (!$tokenExpiration) {
            return false;
        }

        return $tokenExpiration <= (time() + $marginSeconds);
    }

    /**
     * Checks if a token is expired
     *
     * @param SessionInterface $session
     * @return bool
     */
    public function isTokenExpired(SessionInterface $session): bool
    {
        $tokenExpiration = $session->get('keycloak_token_expiration');

        if (!$tokenExpiration) {
            return false;
        }

        return $tokenExpiration <= time();
    }

    /**
     * Attempts to refresh the access token
     *
     * @param SessionInterface $session
     * @return RefreshResult
     */
    public function refreshToken(SessionInterface $session): RefreshResult
    {
        $refreshToken = $session->get(KeycloakConstants::SESSION_REFRESH_TOKEN);

        if (!$refreshToken) {
            $this->logger?->warning('No refresh token available in session');
            return RefreshResult::noRefreshToken();
        }

        try {
            $this->logger?->info('Attempting token refresh');

            $tokens = $this->oidcService->refreshToken($refreshToken);

            // Update tokens in session
            $this->updateTokensInSession($session, $tokens);

            $this->logger?->info('Token refresh successful', [
                'expires_in' => $tokens['expires_in'] ?? 'unknown'
            ]);

            return RefreshResult::success($tokens);

        } catch (ClientExceptionInterface $e) {
            // Client error (400-499) - usually invalid/expired refresh token
            $this->logger?->error('Token refresh failed - client error', [
                'error' => $e->getMessage(),
                'status_code' => $e->getResponse()->getStatusCode()
            ]);

            return RefreshResult::clientError($e->getMessage());

        } catch (ServerExceptionInterface $e) {
            // Server error (500-599) - Keycloak side issue
            $this->logger?->error('Token refresh failed - server error', [
                'error' => $e->getMessage(),
                'status_code' => $e->getResponse()->getStatusCode()
            ]);

            return RefreshResult::serverError($e->getMessage());

        } catch (TransportExceptionInterface $e) {
            // Transport error - network issue
            $this->logger?->error('Token refresh failed - transport error', [
                'error' => $e->getMessage()
            ]);

            return RefreshResult::transportError($e->getMessage());

        } catch (\Exception $e) {
            // Other errors
            $this->logger?->error('Token refresh failed - unexpected error', [
                'error' => $e->getMessage(),
                'class' => get_class($e)
            ]);

            return RefreshResult::unexpectedError($e->getMessage());
        }
    }

    /**
     * Refreshes token if needed (near expiration)
     *
     * @param SessionInterface $session
     * @param int $marginSeconds Margin in seconds before expiration
     * @return RefreshResult
     */
    public function refreshTokenIfNeeded(SessionInterface $session, int $marginSeconds = 60): RefreshResult
    {
        if (!$this->isTokenNearExpiration($session, $marginSeconds)) {
            return RefreshResult::notNeeded();
        }

        return $this->refreshToken($session);
    }

    /**
     * Completely clears the Keycloak session
     *
     * @param SessionInterface $session
     * @param string $reason Reason for clearing (for logs)
     */
    public function clearKeycloakSession(SessionInterface $session, string $reason = 'unknown'): void
    {
        $this->logger?->info('Clearing Keycloak session', ['reason' => $reason]);

        $session->remove(KeycloakConstants::SESSION_ACCESS_TOKEN);
        $session->remove(KeycloakConstants::SESSION_REFRESH_TOKEN);
        $session->remove(KeycloakConstants::SESSION_ID_TOKEN);
        $session->remove(KeycloakConstants::SESSION_TOKEN_EXPIRATION);
        $session->remove(KeycloakConstants::SESSION_USER);
        $session->remove(KeycloakConstants::SESSION_USER_DATA);
        $session->remove(KeycloakConstants::SESSION_CODE_VERIFIER);
        $session->remove(KeycloakConstants::SESSION_STATE);
    }

    /**
     * Updates tokens in session
     *
     * @param SessionInterface $session
     * @param array $tokens
     */
    private function updateTokensInSession(SessionInterface $session, array $tokens): void
    {
        $session->set(KeycloakConstants::SESSION_ACCESS_TOKEN, $tokens['access_token']);
        $session->set(KeycloakConstants::SESSION_REFRESH_TOKEN, $tokens['refresh_token']);
        $session->set(KeycloakConstants::SESSION_TOKEN_EXPIRATION, time() + ($tokens['expires_in'] ?? 3600));

        // Update ID token if present
        if (isset($tokens['id_token'])) {
            $session->set(KeycloakConstants::SESSION_ID_TOKEN, $tokens['id_token']);
        }
    }

    /**
     * Gets statistics about token state
     *
     * @param SessionInterface $session
     * @return array
     */
    public function getTokenStats(SessionInterface $session): array
    {
        $tokenExpiration = $session->get(KeycloakConstants::SESSION_TOKEN_EXPIRATION);
        $hasAccessToken = $session->has(KeycloakConstants::SESSION_ACCESS_TOKEN);
        $hasRefreshToken = $session->has(KeycloakConstants::SESSION_REFRESH_TOKEN);

        $stats = [
            'has_access_token' => $hasAccessToken,
            'has_refresh_token' => $hasRefreshToken,
            'token_expiration' => $tokenExpiration,
            'is_expired' => false,
            'expires_in_seconds' => null,
            'is_near_expiration' => false
        ];

        if ($tokenExpiration) {
            $now = time();
            $stats['is_expired'] = $tokenExpiration <= $now;
            $stats['expires_in_seconds'] = $tokenExpiration - $now;
            $stats['is_near_expiration'] = $this->isTokenNearExpiration($session);
        }

        return $stats;
    }
}


