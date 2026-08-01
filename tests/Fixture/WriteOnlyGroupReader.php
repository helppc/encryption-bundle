<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Fixture;

use HelpPC\EncryptionBundle\Encryption\Decryptor;
use Symfony\Component\DependencyInjection\Attribute\Target;

/**
 * Wiring this has to fail while the container is compiled.
 */
final readonly class WriteOnlyGroupReader
{
    public function __construct(
        #[Target('partner_inbox')] public Decryptor $partnerInbox,
    ) {
    }
}
