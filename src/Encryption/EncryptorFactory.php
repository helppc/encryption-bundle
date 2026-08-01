<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Encryption;

use HelpPC\EncryptionBundle\Exception\InvalidEncryptionConfigurationException;
use SensitiveParameter;
use SodiumException;
use Spaze\Encryption\AnonymousPublicKeyEncryption;
use Spaze\Encryption\AuthenticatedPublicKeyEncryption;
use Spaze\Encryption\Exceptions\IncompleteKeyPairException;
use Spaze\Encryption\Exceptions\InvalidKeyEncodingException;
use Spaze\Encryption\Exceptions\InvalidKeyIdException;
use Spaze\Encryption\Exceptions\InvalidKeyLengthException;
use Spaze\Encryption\Exceptions\InvalidKeyPrefixException;
use Spaze\Encryption\Exceptions\InvalidKeyRoleException;
use Spaze\Encryption\Exceptions\KeyPairMismatchException;
use Spaze\Encryption\Exceptions\UnknownEncryptionKeyIdException;
use Spaze\Encryption\SymmetricKeyEncryption;

final class EncryptorFactory
{
    /**
     * @param array<string, string> $keys key id => key
     * @throws InvalidEncryptionConfigurationException
     */
    public static function createSymmetric(
        string $group,
        #[SensitiveParameter] array $keys,
        string $activeKeyId,
        string $keyPrefix,
    ): SymmetricEncryptor {
        try {
            return new SymmetricEncryptor(new SymmetricKeyEncryption($keys, $activeKeyId, $keyPrefix));
        } catch (
            InvalidKeyEncodingException
            | InvalidKeyIdException
            | InvalidKeyLengthException
            | InvalidKeyPrefixException
            | UnknownEncryptionKeyIdException $exception
        ) {
            throw InvalidEncryptionConfigurationException::forGroup($group, $exception);
        }
    }

    /**
     * @param array<string, string> $secretKeys key id => our secret key
     * @param array<string, string> $publicKeys key id => the other party's public key
     * @throws InvalidEncryptionConfigurationException
     */
    public static function createAsymmetric(
        string $group,
        #[SensitiveParameter] array $secretKeys,
        #[SensitiveParameter] array $publicKeys,
        string $activeKeyId,
        string $keyPrefix,
    ): AsymmetricEncryptor {
        try {
            return new AsymmetricEncryptor(
                new AuthenticatedPublicKeyEncryption($secretKeys, $publicKeys, $activeKeyId, $keyPrefix),
            );
        } catch (
            IncompleteKeyPairException
            | InvalidKeyEncodingException
            | InvalidKeyIdException
            | InvalidKeyLengthException
            | InvalidKeyPrefixException
            | InvalidKeyRoleException
            | UnknownEncryptionKeyIdException $exception
        ) {
            throw InvalidEncryptionConfigurationException::forGroup($group, $exception);
        }
    }

    /**
     * @param array<string, string> $secretKeys key id => secret key
     * @param array<string, string> $publicKeys key id => public key
     * @throws InvalidEncryptionConfigurationException
     */
    public static function createAnonymousAsymmetric(
        string $group,
        #[SensitiveParameter] array $secretKeys,
        #[SensitiveParameter] array $publicKeys,
        string $activeKeyId,
        string $keyPrefix,
    ): AnonymousAsymmetricEncryptor {
        return new AnonymousAsymmetricEncryptor(
            self::createAnonymousPublicKeyEncryption($group, $secretKeys, $publicKeys, $activeKeyId, $keyPrefix),
        );
    }

    /**
     * @param array<string, string> $publicKeys key id => public key
     * @throws InvalidEncryptionConfigurationException
     */
    public static function createWriteOnlyAnonymousAsymmetric(
        string $group,
        #[SensitiveParameter] array $publicKeys,
        string $activeKeyId,
        string $keyPrefix,
    ): WriteOnlyAnonymousAsymmetricEncryptor {
        return new WriteOnlyAnonymousAsymmetricEncryptor(
            self::createAnonymousPublicKeyEncryption($group, [], $publicKeys, $activeKeyId, $keyPrefix),
        );
    }

    /**
     * @param array<string, string> $secretKeys
     * @param array<string, string> $publicKeys
     * @throws InvalidEncryptionConfigurationException
     */
    private static function createAnonymousPublicKeyEncryption(
        string $group,
        #[SensitiveParameter] array $secretKeys,
        #[SensitiveParameter] array $publicKeys,
        string $activeKeyId,
        string $keyPrefix,
    ): AnonymousPublicKeyEncryption {
        try {
            return new AnonymousPublicKeyEncryption($secretKeys, $publicKeys, $activeKeyId, $keyPrefix);
        } catch (
            InvalidKeyEncodingException
            | InvalidKeyIdException
            | InvalidKeyLengthException
            | InvalidKeyPrefixException
            | InvalidKeyRoleException
            | KeyPairMismatchException
            | SodiumException
            | UnknownEncryptionKeyIdException $exception
        ) {
            throw InvalidEncryptionConfigurationException::forGroup($group, $exception);
        }
    }
}
