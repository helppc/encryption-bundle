<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Encryption;

use HelpPC\EncryptionBundle\Exception\DecryptionException;

interface AdditionalDataDecryptor extends Decryptor
{
    /**
     * @throws DecryptionException when the additional data is empty, does not match what was used
     *                             for encryption, or decryption fails
     */
    public function decryptWithAdditionalData(string $cipherText, string $additionalData): string;
}
