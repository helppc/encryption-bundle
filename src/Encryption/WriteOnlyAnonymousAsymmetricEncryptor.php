<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Encryption;

use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use ParagonIE\Halite\Alerts\HaliteAlert;
use SensitiveParameter;
use SodiumException;
use Spaze\Encryption\AnonymousPublicKeyEncryption;
use Spaze\Encryption\Exceptions\FormatMarkerMismatchException;
use Spaze\Encryption\Exceptions\InvalidCipherTextFormatException;
use Spaze\Encryption\Exceptions\UnknownFormatMarkerException;
use TypeError;

/**
 * Not implementing Decryptor is the point: type-hinting one for a public-keys-only group fails
 * while the container is compiled, not on the first read attempt in production.
 */
final readonly class WriteOnlyAnonymousAsymmetricEncryptor implements Encryptor
{
    public function __construct(private AnonymousPublicKeyEncryption $encryption)
    {
    }

    /**
     * @throws EncryptionException
     */
    public function encrypt(#[SensitiveParameter] string $plainText): string
    {
        try {
            return $this->encryption->encrypt($plainText);
        } catch (HaliteAlert | SodiumException | TypeError $exception) {
            throw new EncryptionException($exception->getMessage(), $exception->getCode(), $exception);
        }
    }

    public function isEncrypted(string $value): bool
    {
        try {
            $this->encryption->needsReEncrypt($value);

            return true;
        } catch (
            FormatMarkerMismatchException
            | InvalidCipherTextFormatException
            | UnknownFormatMarkerException
        ) {
            return false;
        }
    }

    /**
     * @throws DecryptionException
     */
    public function needsReEncryption(string $value): bool
    {
        try {
            return $this->encryption->needsReEncrypt($value);
        } catch (
            FormatMarkerMismatchException
            | InvalidCipherTextFormatException
            | UnknownFormatMarkerException $exception
        ) {
            throw new DecryptionException($exception->getMessage(), $exception->getCode(), $exception);
        }
    }
}
