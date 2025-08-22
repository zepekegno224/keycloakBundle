<?php

namespace Zepekegno\KeycloakBundle\Constants;

/**
 * Constants for the Keycloak bundle
 *
 * This class centralizes all constants used in the bundle
 * for session variables and route names.
 */
final class KeycloakConstants
{
    // ========================================
    // SESSION VARIABLES
    // ========================================

    /**
     * Authentication tokens
     */
    public const SESSION_ACCESS_TOKEN = 'keycloak_access_token';
    public const SESSION_REFRESH_TOKEN = 'keycloak_refresh_token';
    public const SESSION_ID_TOKEN = 'keycloak_id_token';
    public const SESSION_TOKEN_EXPIRATION = 'keycloak_token_expiration';

    /**
     * User data
     */
    public const SESSION_USER = 'keycloak_user';
    public const SESSION_USER_DATA = 'keycloak_user_data';

    /**
     * PKCE and state data
     */
    public const SESSION_CODE_VERIFIER = 'keycloak_code_verifier';
    public const SESSION_STATE = 'keycloak_state';

    /**
     * Temporary data (for compatibility)
     */
    public const SESSION_TOKENS = 'keycloak_tokens';

    // ========================================
    // ROUTE NAMES
    // ========================================

    /**
     * Main authentication routes
     */
    public const ROUTE_LOGIN = 'keycloak_login';
    public const ROUTE_CALLBACK = 'keycloak_callback';
    public const ROUTE_LOGOUT = 'keycloak_logout';
    public const ROUTE_PROFILE = 'keycloak_profile';

    /**
     * Registration routes (if implemented)
     */
    public const ROUTE_REGISTER = 'keycloak_register';

    // ========================================
    // CONFIGURATION PARAMETERS
    // ========================================

    /**
     * Bundle configuration parameters
     */
    public const CONFIG_BASE_URL = 'keycloak.base_url';
    public const CONFIG_REALM = 'keycloak.realm';
    public const CONFIG_CLIENT_ID = 'keycloak.client_id';
    public const CONFIG_CLIENT_SECRET = 'keycloak.client_secret';
    public const CONFIG_ADMIN_CLIENT_ID = 'keycloak.admin_client_id';
    public const CONFIG_ADMIN_CLIENT_SECRET = 'keycloak.admin_client_secret';
    public const CONFIG_PUBLIC_KEY = 'keycloak.public_key';
    public const CONFIG_VERIFY_TOKEN = 'keycloak.verify_token';
    public const CONFIG_ALGORITHM = 'keycloak.algorithm';
    public const CONFIG_SCOPE = 'keycloak.scope';
    public const CONFIG_REDIRECT_ROUTE = 'keycloak.redirect_routes';


    // ========================================
    // ERROR CODES
    // ========================================

    /**
     * Bundle-specific error codes
     */
    public const ERROR_CODE_KEYCLOAK = 'KEYCLOAK_ERROR';
    public const ERROR_CODE_TOKEN_EXPIRED = 'TOKEN_EXPIRED';
    public const ERROR_CODE_INVALID_TOKEN = 'INVALID_TOKEN';
    public const ERROR_CODE_REFRESH_FAILED = 'REFRESH_FAILED';

    // ========================================
    // UTILITY METHODS
    // ========================================

    /**
     * Returns all Keycloak session keys
     *
     * @return array<string>
     */
    public static function getAllSessionKeys(): array
    {
        return [
            self::SESSION_ACCESS_TOKEN,
            self::SESSION_REFRESH_TOKEN,
            self::SESSION_ID_TOKEN,
            self::SESSION_TOKEN_EXPIRATION,
            self::SESSION_USER,
            self::SESSION_USER_DATA,
            self::SESSION_CODE_VERIFIER,
            self::SESSION_STATE,
            self::SESSION_TOKENS,
        ];
    }

    /**
     * Returns all Keycloak routes
     *
     * @return array<string>
     */
    public static function getAllRoutes(): array
    {
        return [
            self::ROUTE_LOGIN,
            self::ROUTE_CALLBACK,
            self::ROUTE_LOGOUT,
            self::ROUTE_PROFILE,
            self::ROUTE_REGISTER,
        ];
    }

    /**
     * Returns all configuration parameters
     *
     * @return array<string>
     */
    public static function getAllConfigParameters(): array
    {
        return [
            self::CONFIG_BASE_URL,
            self::CONFIG_REALM,
            self::CONFIG_CLIENT_ID,
            self::CONFIG_CLIENT_SECRET,
            self::CONFIG_ADMIN_CLIENT_ID,
            self::CONFIG_ADMIN_CLIENT_SECRET,
            self::CONFIG_PUBLIC_KEY,
            self::CONFIG_VERIFY_TOKEN,
        ];
    }
}
