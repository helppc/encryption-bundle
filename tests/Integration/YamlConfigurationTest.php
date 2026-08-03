<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Integration;

use HelpPC\EncryptionBundle\Encryption\AnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\AsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\SymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\WriteOnlyAnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\EncryptionBundle;
use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKernel;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKeys;
use HelpPC\EncryptionBundle\Tests\Fixture\YamlConfiguredConsumer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\ErrorHandler\ErrorHandler;
use Symfony\Component\Filesystem\Filesystem;

use function is_array;
use function restore_exception_handler;
use function set_exception_handler;

/**
 * YAML cannot hold a PHP value, but Symfony's !php/enum tag resolves one while parsing, and the
 * config node accepts it because it is bound to the enum rather than to a list of strings.
 */
#[CoversClass(EncryptionBundle::class)]
final class YamlConfigurationTest extends TestCase
{
    protected function setUp(): void
    {
        $_ENV['TEST_SYMMETRIC_V1'] = TestKeys::SYMMETRIC_V1;
        $_ENV['TEST_ALICE_PUBLIC_V1'] = TestKeys::ALICE_PUBLIC_V1;
        $_ENV['TEST_ALICE_SECRET_V1'] = TestKeys::ALICE_SECRET_V1;
        $_ENV['TEST_BOB_PUBLIC_V1'] = TestKeys::BOB_PUBLIC_V1;
    }

    public function testEnumTagAndPlainStringBuildTheSameKindOfGroups(): void
    {
        $kernel = $this->boot();

        try {
            $consumer = $this->consumer($kernel);

            self::assertInstanceOf(SymmetricEncryptor::class, $consumer->encryptor);
            self::assertInstanceOf(AnonymousAsymmetricEncryptor::class, $consumer->vault);
            self::assertInstanceOf(WriteOnlyAnonymousAsymmetricEncryptor::class, $consumer->partnerInbox);
            self::assertInstanceOf(AsymmetricEncryptor::class, $consumer->peer);
        } finally {
            $this->shutdown($kernel);
        }
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testGroupsDeclaredWithTheEnumTagActuallyWork(): void
    {
        $kernel = $this->boot();

        try {
            $consumer = $this->consumer($kernel);

            $sealed = $consumer->partnerInbox->encrypt('Ke Karlovu 2027/3');
            self::assertSame('Ke Karlovu 2027/3', $consumer->vault->decrypt($sealed));

            $bound = $consumer->peer->encryptWithAdditionalData('Malostranské náměstí 25', 'tenant-42');
            self::assertNotSame('Malostranské náměstí 25', $bound);
            self::assertSame(
                'Malostranské náměstí 25',
                $consumer->peerReader->decryptWithAdditionalData($bound, 'tenant-42'),
            );
        } finally {
            $this->shutdown($kernel);
        }
    }

    /**
     * The additional data is only bound when it is byte identical, which is what makes a cipher
     * text unusable in another row or another tenant.
     *
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testTheYamlConfiguredPeerBindsItsAdditionalData(): void
    {
        $kernel = $this->boot();

        try {
            $consumer = $this->consumer($kernel);
            $bound = $consumer->peer->encryptWithAdditionalData('Malostranské náměstí 25', 'tenant-42');

            $this->expectException(DecryptionException::class);
            $consumer->peerReader->decryptWithAdditionalData($bound, 'tenant-43');
        } finally {
            $this->shutdown($kernel);
        }
    }

    private function boot(): TestKernel
    {
        $kernel = new TestKernel(
            __DIR__ . '/../Fixture/config/enum_tag.yaml',
            [YamlConfiguredConsumer::class],
        );
        $kernel->boot();

        return $kernel;
    }

    private function consumer(TestKernel $kernel): YamlConfiguredConsumer
    {
        $consumer = $kernel->getContainer()->get(YamlConfiguredConsumer::class);
        self::assertInstanceOf(YamlConfiguredConsumer::class, $consumer);

        return $consumer;
    }

    private function shutdown(TestKernel $kernel): void
    {
        $cacheDir = $kernel->getCacheDir();
        $kernel->shutdown();
        new Filesystem()->remove($cacheDir);

        $handler = set_exception_handler(null);
        restore_exception_handler();
        if (!is_array($handler) || !$handler[0] instanceof ErrorHandler) {
            return;
        }

        restore_exception_handler();
    }
}
