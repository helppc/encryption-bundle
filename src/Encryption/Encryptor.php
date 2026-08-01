<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Encryption;

use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use SensitiveParameter;

interface Encryptor
{
    /**
     * @throws EncryptionException
     */
    public function encrypt(#[SensitiveParameter] string $plainText): string;

    /**
     * Never throws, unlike needsReEncryption(), so it can scan a column holding a mix of plain and
     * encrypted values. The check is structural: a value written by another group of the same type
     * passes here and fails on decrypt.
     */
    public function isEncrypted(string $value): bool;

    /**
     * @throws DecryptionException when the value is not cipher text of this group
     */
    public function needsReEncryption(string $value): bool;
}
