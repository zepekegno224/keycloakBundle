# Keycloak Bundle Constants

This document describes the usage of centralized constants in the Keycloak bundle.

## KeycloakConstants Class

The `Zepekegno\KeycloakBundle\Constants\KeycloakConstants` class centralizes all constants used in the bundle to avoid magic strings and facilitate maintenance.

### Session Variables

#### Authentication tokens

```php
KeycloakConstants::SESSION_ACCESS_TOKEN = 'keycloak_access_token'
KeycloakConstants::SESSION_REFRESH_TOKEN = 'keycloak_refresh_token'
KeycloakConstants::SESSION_ID_TOKEN = 'keycloak_id_token'
KeycloakConstants::SESSION_TOKEN_EXPIRATION = 'keycloak_token_expiration'
```

#### User data

```php
KeycloakConstants::SESSION_USER = 'keycloak_user'
KeycloakConstants::SESSION_USER_DATA = 'keycloak_user_data'
```

#### PKCE and state data

```php
KeycloakConstants::SESSION_CODE_VERIFIER = 'keycloak_code_verifier'
KeycloakConstants::SESSION_STATE = 'keycloak_state'
```

### Route Names

```php
KeycloakConstants::ROUTE_LOGIN = 'keycloak_login'
KeycloakConstants::ROUTE_CALLBACK = 'keycloak_callback'
KeycloakConstants::ROUTE_LOGOUT = 'keycloak_logout'
KeycloakConstants::ROUTE_PROFILE = 'keycloak_profile'
KeycloakConstants::ROUTE_REGISTER = 'keycloak_register'
```

### Configuration Parameters

```php
KeycloakConstants::CONFIG_BASE_URL = 'keycloak.base_url'
KeycloakConstants::CONFIG_REALM = 'keycloak.realm'
KeycloakConstants::CONFIG_CLIENT_ID = 'keycloak.client_id'
// ... etc
```

### Environment Variables

```php
KeycloakConstants::ENV_BASE_URL = 'KEYCLOAK_BASE_URL'
KeycloakConstants::ENV_REALM = 'KEYCLOAK_REALM'
// ... etc
```

## Usage

### In a controller

```php
use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;

class MyController extends AbstractController
{
    public function myAction(SessionInterface $session)
    {
        // Instead of:
        // $token = $session->get('keycloak_access_token');
    
        // Use:
        $token = $session->get(KeycloakConstants::SESSION_ACCESS_TOKEN);
    
        // Instead of:
        // return $this->redirectToRoute('keycloak_login');
    
        // Use:
        return $this->redirectToRoute(KeycloakConstants::ROUTE_LOGIN);
    }
}
```

### In a service

```php
use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;

class MyService
{
    public function clearSession(SessionInterface $session)
    {
        // Instead of:
        // $session->remove('keycloak_access_token');
        // $session->remove('keycloak_refresh_token');
    
        // Use:
        $session->remove(KeycloakConstants::SESSION_ACCESS_TOKEN);
        $session->remove(KeycloakConstants::SESSION_REFRESH_TOKEN);
    }
}
```

### In route annotations

```php
use Zepekegno\KeycloakBundle\Constants\KeycloakConstants;

class AuthController extends AbstractController
{
    // Instead of:
    // #[Route('/login', name: 'keycloak_login')]
  
    // Use:
    #[Route('/login', name: KeycloakConstants::ROUTE_LOGIN)]
    public function login(): Response
    {
        // ...
    }
}
```

## Utility Methods

The `KeycloakConstants` class also provides utility methods:

```php
// Get all session keys
$sessionKeys = KeycloakConstants::getAllSessionKeys();

// Get all routes
$routes = KeycloakConstants::getAllRoutes();

// Get all configuration parameters
$configParams = KeycloakConstants::getAllConfigParameters();

// Get all environment variables
$envVars = KeycloakConstants::getAllEnvironmentVariables();
```

## Advantages

1. **Easier maintenance**: Centralized name changes
2. **IDE autocompletion**: Full IDE support
3. **Error detection**: Compilation errors instead of runtime errors
4. **Safe refactoring**: Automatic renaming throughout the code
5. **Documentation**: Constants serve as documentation

## Migration

If you have existing code using hard-coded strings, you can easily migrate:

```php
// Before
$session->get('keycloak_access_token')
$this->redirectToRoute('keycloak_login')

// After
$session->get(KeycloakConstants::SESSION_ACCESS_TOKEN)
$this->redirectToRoute(KeycloakConstants::ROUTE_LOGIN)
```

## Best Practices

1. **Always import** the `KeycloakConstants` class at the top of your files
2. **Use constants** instead of string literals
3. **Don't redefine** constant values
4. **Use IDE autocompletion** to avoid typos
