<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Encryption;

use HelpPC\EncryptionBundle\Exception\DecryptionException;

interface Decryptor
{
    /**
     * @throws DecryptionException
     */
    public function decrypt(string $cipherText): string;
}
