<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Fixture;

use HelpPC\EncryptionBundle\Encryption\AdditionalDataEncryptor;
use HelpPC\EncryptionBundle\Encryption\Decryptor;
use HelpPC\EncryptionBundle\Encryption\Encryptor;
use Symfony\Component\DependencyInjection\Attribute\Target;

final readonly class YamlConfiguredConsumer
{
    public function __construct(
        public Encryptor $encryptor,
        public Decryptor $decryptor,
        #[Target('vault')] public Decryptor $vault,
        #[Target('partner_inbox')] public Encryptor $partnerInbox,
        #[Target('peer')] public AdditionalDataEncryptor $peer,
    ) {
    }
}
