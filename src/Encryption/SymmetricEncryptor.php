<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Encryption;

use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use ParagonIE\Halite\Alerts\HaliteAlert;
use SensitiveParameter;
use SodiumException;
use Spaze\Encryption\Exceptions\DecryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\EncryptWithAdNeedsAdditionalDataException;
use Spaze\Encryption\Exceptions\InvalidCipherTextFormatException;
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use Spaze\Encryption\SymmetricKeyEncryption;
use TypeError;

final readonly class SymmetricEncryptor implements AdditionalDataDecryptor, AdditionalDataEncryptor
{
    public function __construct(private SymmetricKeyEncryption $encryption)
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
     * @throws EncryptionException
     */
    public function encryptWithAdditionalData(
        #[SensitiveParameter] string $plainText,
        string $additionalData,
    ): string {
        try {
            return $this->encryption->encryptWithAd($plainText, $additionalData);
        } catch (
            EncryptWithAdNeedsAdditionalDataException
            | HaliteAlert
            | SodiumException
            | TypeError $exception
        ) {
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
            HaliteAlert
            | InvalidCipherTextFormatException
            | SodiumException
            | TypeError
            | UnknownEncryptionKeyIdException $exception
        ) {
            throw new DecryptionException($exception->getMessage(), $exception->getCode(), $exception);
        }
    }

    /**
     * @throws DecryptionException
     */
    public function decryptWithAdditionalData(string $cipherText, string $additionalData): string
    {
        try {
            return $this->encryption->decryptWithAd($cipherText, $additionalData);
        } catch (
            DecryptWithAdNeedsAdditionalDataException
            | HaliteAlert
            | InvalidCipherTextFormatException
            | SodiumException
            | TypeError
            | UnknownEncryptionKeyIdException $exception
        ) {
            throw new DecryptionException($exception->getMessage(), $exception->getCode(), $exception);
        }
    }

    public function isEncrypted(string $value): bool
    {
        try {
            $this->encryption->needsReEncrypt($value);

            return true;
        } catch (InvalidCipherTextFormatException) {
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
        } catch (InvalidCipherTextFormatException $exception) {
            throw new DecryptionException($exception->getMessage(), $exception->getCode(), $exception);
        }
    }
}
