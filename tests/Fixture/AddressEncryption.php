<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Fixture;

use HelpPC\EncryptionBundle\Encryption\AdditionalDataDecryptor;
use HelpPC\EncryptionBundle\Encryption\AdditionalDataEncryptor;
use HelpPC\EncryptionBundle\Encryption\Decryptor;
use HelpPC\EncryptionBundle\Encryption\Encryptor;
use Symfony\Component\DependencyInjection\Attribute\Target;

final readonly class AddressEncryption
{
    public function __construct(
        public Encryptor $encryptor,
        public Decryptor $decryptor,
        public AdditionalDataEncryptor $additionalDataEncryptor,
        public AdditionalDataDecryptor $additionalDataDecryptor,
        #[Target('partner_inbox')] public Encryptor $partnerInbox,
        #[Target('vault')] public Decryptor $vault,
        #[Target('vault')] public Encryptor $vaultWriter,
    ) {
    }
}
