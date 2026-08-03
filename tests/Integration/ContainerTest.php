<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Integration;

use HelpPC\EncryptionBundle\Encryption\AnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\SymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\WriteOnlyAnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\EncryptionBundle;
use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use HelpPC\EncryptionBundle\Exception\InvalidEncryptionConfigurationException;
use HelpPC\EncryptionBundle\Tests\Fixture\AddressEncryption;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKernel;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKeys;
use HelpPC\EncryptionBundle\Tests\Fixture\WriteOnlyGroupReader;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Exception\RuntimeException as ContainerRuntimeException;
use Symfony\Component\ErrorHandler\ErrorHandler;
use Symfony\Component\Filesystem\Filesystem;

use function is_array;
use function restore_exception_handler;
use function set_exception_handler;

#[CoversClass(EncryptionBundle::class)]
final class ContainerTest extends TestCase
{
    public function testGroupsAreWiredAndUsable(): void
    {
        $kernel = $this->boot([AddressEncryption::class]);

        try {
            $consumer = $this->consumer($kernel);

            self::assertInstanceOf(SymmetricEncryptor::class, $consumer->encryptor);
            self::assertInstanceOf(AnonymousAsymmetricEncryptor::class, $consumer->vault);
            self::assertInstanceOf(WriteOnlyAnonymousAsymmetricEncryptor::class, $consumer->partnerInbox);
        } finally {
            $this->shutdown($kernel);
        }
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testTheDefaultGroupEncryptsAndDecrypts(): void
    {
        $kernel = $this->boot([AddressEncryption::class]);

        try {
            $consumer = $this->consumer($kernel);

            $cipherText = $consumer->encryptor->encrypt('Ke Karlovu 2027/3');
            self::assertSame('Ke Karlovu 2027/3', $consumer->decryptor->decrypt($cipherText));

            $bound = $consumer->additionalDataEncryptor->encryptWithAdditionalData(
                'Ke Karlovu 2027/3',
                'tenant-42',
            );
            self::assertSame(
                'Ke Karlovu 2027/3',
                $consumer->additionalDataDecryptor->decryptWithAdditionalData($bound, 'tenant-42'),
            );
        } finally {
            $this->shutdown($kernel);
        }
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testWhatTheWriteOnlyGroupSealsIsReadableWhereTheSecretKeyLives(): void
    {
        $kernel = $this->boot([AddressEncryption::class]);

        try {
            $consumer = $this->consumer($kernel);

            $sealed = $consumer->partnerInbox->encrypt('Ke Karlovu 2027/3');
            self::assertSame('Ke Karlovu 2027/3', $consumer->vault->decrypt($sealed));
        } finally {
            $this->shutdown($kernel);
        }
    }

    public function testReadingAWriteOnlyGroupFailsWhileTheContainerIsCompiled(): void
    {
        $kernel = new TestKernel($this->configuration(), [WriteOnlyGroupReader::class]);

        try {
            $this->expectException(ContainerRuntimeException::class);
            $kernel->boot();
        } finally {
            $this->shutdown($kernel);
        }
    }

    public function testMisconfiguredGroupFailsWhenTheServiceIsBuilt(): void
    {
        $kernel = new TestKernel(
            $this->configuration('wrongprefix_' . TestKeys::SYMMETRIC_V1),
            [AddressEncryption::class],
        );
        $kernel->boot();

        try {
            $this->expectException(InvalidEncryptionConfigurationException::class);
            $kernel->getContainer()->get(AddressEncryption::class);
        } finally {
            $this->shutdown($kernel);
        }
    }

    /**
     * @param list<class-string> $consumers
     */
    private function boot(array $consumers): TestKernel
    {
        $kernel = new TestKernel($this->configuration(), $consumers);
        $kernel->boot();

        return $kernel;
    }

    private function consumer(TestKernel $kernel): AddressEncryption
    {
        $consumer = $kernel->getContainer()->get(AddressEncryption::class);
        self::assertInstanceOf(AddressEncryption::class, $consumer);

        return $consumer;
    }

    private function shutdown(TestKernel $kernel): void
    {
        $cacheDir = $kernel->getCacheDir();
        $kernel->shutdown();
        new Filesystem()->remove($cacheDir);
        $this->restoreHandlers();
    }

    /**
     * FrameworkBundle::boot() leaves Symfony's exception handler behind and nothing removes it,
     * which PHPUnit reports as a risky test. The error handler restores itself.
     */
    private function restoreHandlers(): void
    {
        $handler = set_exception_handler(null);
        restore_exception_handler();
        if (!is_array($handler) || !$handler[0] instanceof ErrorHandler) {
            return;
        }

        restore_exception_handler();
    }

    /**
     * @return array<string, mixed>
     */
    private function configuration(string $legacySymmetricKey = TestKeys::SYMMETRIC_V1): array
    {
        return [
            'default_group' => 'default',
            'groups' => [
                'default' => [
                    'key_prefix' => TestKeys::PREFIX,
                    'active_key' => 'v2',
                    'keys' => [
                        'v1' => $legacySymmetricKey,
                        'v2' => TestKeys::SYMMETRIC_V2,
                    ],
                ],
                'vault' => [
                    'type' => 'anonymous_asymmetric',
                    'key_prefix' => TestKeys::PREFIX,
                    'active_key' => 'v1',
                    'keys' => [
                        'v1' => [
                            'public_key' => TestKeys::ALICE_PUBLIC_V1,
                            'secret_key' => TestKeys::ALICE_SECRET_V1,
                        ],
                    ],
                ],
                'partner_inbox' => [
                    'type' => 'anonymous_asymmetric',
                    'key_prefix' => TestKeys::PREFIX,
                    'active_key' => 'v1',
                    'keys' => ['v1' => ['public_key' => TestKeys::ALICE_PUBLIC_V1]],
                ],
            ],
        ];
    }
}
