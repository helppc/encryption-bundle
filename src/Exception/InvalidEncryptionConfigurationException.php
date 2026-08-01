<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Exception;

use RuntimeException;
use Throwable;

use function sprintf;

/**
 * A deployment mistake, not something a caller can recover from — hence unchecked.
 */
final class InvalidEncryptionConfigurationException extends RuntimeException
{
    public static function forGroup(string $group, Throwable $previous): self
    {
        return new self(
            sprintf('Encryption group "%s" is misconfigured: %s', $group, $previous->getMessage()),
            0,
            $previous,
        );
    }
}
