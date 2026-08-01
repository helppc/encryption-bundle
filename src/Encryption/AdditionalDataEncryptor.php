<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Encryption;

use HelpPC\EncryptionBundle\Exception\EncryptionException;
use SensitiveParameter;

interface AdditionalDataEncryptor extends Encryptor
{
    /**
     * The additional data is authenticated but not encrypted, so it must not be a secret. It ties
     * the cipher text to a context — a row id, a column name, a tenant id — so a valid value cannot
     * be copied elsewhere. Decryption needs the byte identical value.
     *
     * @throws EncryptionException when the additional data is empty, or encryption fails
     */
    public function encryptWithAdditionalData(
        #[SensitiveParameter] string $plainText,
        string $additionalData,
    ): string;
}
