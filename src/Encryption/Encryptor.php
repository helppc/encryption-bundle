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
     * True when the value carries a key id other than the active one, or no format marker at all,
     * which is how values written before the marker existed look.
     *
     * The check is structural, like isEncrypted(): it reads the envelope and the marker, and it
     * decrypts nothing. It does not verify that the key id is one of the configured ones, and it
     * does not authenticate the payload — a value with an unknown key id reports true, and only
     * decrypt() then fails. Migration code must not read this as proof that the value belongs to
     * this group.
     *
     * @throws DecryptionException when the value is not shaped like cipher text at all, or carries
     *                             a marker written by a different encryption type
     */
    public function needsReEncryption(string $value): bool;
}
