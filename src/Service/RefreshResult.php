<?php
    namespace Zepekegno\KeycloakBundle\Service;
    /**
 * Class to encapsulate the result of a refresh attempt
 */
final class RefreshResult
{
    public const STATUS_SUCCESS = 'success';
    public const STATUS_NOT_NEEDED = 'not_needed';
    public const STATUS_NO_REFRESH_TOKEN = 'no_refresh_token';
    public const STATUS_CLIENT_ERROR = 'client_error';
    public const STATUS_SERVER_ERROR = 'server_error';
    public const STATUS_TRANSPORT_ERROR = 'transport_error';
    public const STATUS_UNEXPECTED_ERROR = 'unexpected_error';

    private function __construct(
        private string $status,
        private ?array $tokens = null,
        private ?string $errorMessage = null
    ) {
    }

    public static function success(array $tokens): self
    {
        return new self(self::STATUS_SUCCESS, $tokens);
    }

    public static function notNeeded(): self
    {
        return new self(self::STATUS_NOT_NEEDED);
    }

    public static function noRefreshToken(): self
    {
        return new self(self::STATUS_NO_REFRESH_TOKEN);
    }

    public static function clientError(string $message): self
    {
        return new self(self::STATUS_CLIENT_ERROR, null, $message);
    }

    public static function serverError(string $message): self
    {
        return new self(self::STATUS_SERVER_ERROR, null, $message);
    }

    public static function transportError(string $message): self
    {
        return new self(self::STATUS_TRANSPORT_ERROR, null, $message);
    }

    public static function unexpectedError(string $message): self
    {
        return new self(self::STATUS_UNEXPECTED_ERROR, null, $message);
    }

    public function isSuccess(): bool
    {
        return $this->status === self::STATUS_SUCCESS;
    }

    public function isNotNeeded(): bool
    {
        return $this->status === self::STATUS_NOT_NEEDED;
    }

    public function isError(): bool
    {
        return !in_array($this->status, [self::STATUS_SUCCESS, self::STATUS_NOT_NEEDED]);
    }

    public function shouldClearSession(): bool
    {
        // Clear session for client errors (invalid/expired token)
        return $this->status === self::STATUS_CLIENT_ERROR ||
               $this->status === self::STATUS_NO_REFRESH_TOKEN;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getTokens(): ?array
    {
        return $this->tokens;
    }

    public function getErrorMessage(): ?string
    {
        return $this->errorMessage;
    }
}
