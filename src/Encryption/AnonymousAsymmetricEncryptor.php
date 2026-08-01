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
use Spaze\Encryption\Exceptions\MissingSecretKeyException;
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use Spaze\Encryption\Exceptions\UnknownFormatMarkerException;
use TypeError;

/**
 * Halite's sealed box API takes no additional data, hence neither AdditionalData* interface here.
 */
final readonly class AnonymousAsymmetricEncryptor implements Decryptor, Encryptor
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

    /**
     * @throws DecryptionException
     */
    public function decrypt(string $cipherText): string
    {
        try {
            return $this->encryption->decrypt($cipherText);
        } catch (
            FormatMarkerMismatchException
            | HaliteAlert
            | InvalidCipherTextFormatException
            | MissingSecretKeyException
            | SodiumException
            | TypeError
            | UnknownEncryptionKeyIdException
            | UnknownFormatMarkerException $exception
        ) {
            throw new DecryptionException($exception->getMessage(), $exception->getCode(), $exception);
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
