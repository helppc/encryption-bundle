<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Unit\Encryption;

use HelpPC\EncryptionBundle\Encryption\AdditionalDataDecryptor;
use HelpPC\EncryptionBundle\Encryption\AdditionalDataEncryptor;
use HelpPC\EncryptionBundle\Encryption\AnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\Decryptor;
use HelpPC\EncryptionBundle\Encryption\Encryptor;
use HelpPC\EncryptionBundle\Encryption\EncryptorFactory;
use HelpPC\EncryptionBundle\Encryption\WriteOnlyAnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use HelpPC\EncryptionBundle\Exception\InvalidEncryptionConfigurationException;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKeys;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

use function print_r;
use function str_contains;
use function substr;

/**
 * Sealed boxes: the public key encrypts, the secret key reads, and the value says nothing about
 * who wrote it.
 */
#[CoversClass(AnonymousAsymmetricEncryptor::class)]
#[CoversClass(WriteOnlyAnonymousAsymmetricEncryptor::class)]
#[CoversClass(EncryptorFactory::class)]
final class AnonymousAsymmetricEncryptorTest extends TestCase
{
    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testRoundTrip(): void
    {
        $vault = $this->vault();

        self::assertSame('Ke Karlovu 2027/3', $vault->decrypt($vault->encrypt('Ke Karlovu 2027/3')));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testWhatAWriteOnlyGroupEncryptsIsReadableByTheSecretKeyHolder(): void
    {
        $sealed = $this->writeOnly()->encrypt('Ke Karlovu 2027/3');

        self::assertSame('Ke Karlovu 2027/3', $this->vault()->decrypt($sealed));
    }

    public function testWriteOnlyGroupHasNoWayToDecrypt(): void
    {
        $implemented = $this->interfacesOf(WriteOnlyAnonymousAsymmetricEncryptor::class);

        self::assertContains(Encryptor::class, $implemented);
        self::assertNotContains(Decryptor::class, $implemented);
    }

    public function testAnonymousGroupsOfferNoAdditionalData(): void
    {
        $readable = $this->interfacesOf(AnonymousAsymmetricEncryptor::class);

        self::assertNotContains(AdditionalDataEncryptor::class, $readable);
        self::assertNotContains(AdditionalDataDecryptor::class, $readable);
        self::assertNotContains(
            AdditionalDataEncryptor::class,
            $this->interfacesOf(WriteOnlyAnonymousAsymmetricEncryptor::class),
        );
    }

    /**
     * @throws EncryptionException
     */
    public function testEncryptingTheSameValueTwiceGivesDifferentCipherText(): void
    {
        $vault = $this->vault();

        self::assertNotSame($vault->encrypt('same'), $vault->encrypt('same'));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testOlderKeyStaysReadableAndIsReportedForReEncryption(): void
    {
        $writtenWithV1 = $this->vault('v1')->encrypt('Ke Karlovu 2027/3');
        $current = $this->vault('v2');

        self::assertSame('Ke Karlovu 2027/3', $current->decrypt($writtenWithV1));
        self::assertTrue($current->needsReEncryption($writtenWithV1));
        self::assertFalse($current->needsReEncryption($current->encrypt('Ke Karlovu 2027/3')));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testAValueSealedForSomeoneElseCannotBeRead(): void
    {
        $forBob = EncryptorFactory::createWriteOnlyAnonymousAsymmetric(
            'bob_inbox',
            ['v1' => TestKeys::BOB_PUBLIC_V1],
            'v1',
            TestKeys::PREFIX,
        )->encrypt('Ke Karlovu 2027/3');

        $this->expectException(DecryptionException::class);
        $this->vault()->decrypt($forBob);
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testAuthenticatedCipherTextIsNotAcceptedHere(): void
    {
        $authenticated = EncryptorFactory::createAsymmetric(
            'alice',
            ['v1' => TestKeys::ALICE_SECRET_V1],
            ['v1' => TestKeys::BOB_PUBLIC_V1],
            'v1',
            TestKeys::PREFIX,
        )->encrypt('Ke Karlovu 2027/3');

        self::assertFalse($this->vault()->isEncrypted($authenticated));

        $this->expectException(DecryptionException::class);
        $this->vault()->decrypt($authenticated);
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testPlainTextIsNotMistakenForCipherText(): void
    {
        $vault = $this->vault();

        self::assertFalse($vault->isEncrypted('Ke Karlovu 2027/3'));
        self::assertTrue($vault->isEncrypted($vault->encrypt('Ke Karlovu 2027/3')));

        $this->expectException(DecryptionException::class);
        $vault->needsReEncryption('Ke Karlovu 2027/3');
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testTruncatedCipherTextFailsToDecrypt(): void
    {
        $vault = $this->vault();
        $sealed = $vault->encrypt('Ke Karlovu 2027/3');

        $this->expectException(DecryptionException::class);
        $vault->decrypt(substr($sealed, 0, -4));
    }

    public function testSecretKeyDoesNotLeakIntoDebugOutput(): void
    {
        $dump = print_r($this->vault(), true);

        self::assertFalse(str_contains($dump, substr(TestKeys::ALICE_SECRET_V1, 12)));
        self::assertFalse(str_contains($dump, substr(TestKeys::ALICE_SECRET_V2, 12)));
    }

    public function testAPublicKeyThatDoesNotBelongToTheSecretKeyIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        EncryptorFactory::createAnonymousAsymmetric(
            'test',
            ['v1' => TestKeys::ALICE_SECRET_V1],
            ['v1' => TestKeys::BOB_PUBLIC_V1],
            'v1',
            TestKeys::PREFIX,
        );
    }

    public function testActiveKeyHasToBeConfigured(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        EncryptorFactory::createWriteOnlyAnonymousAsymmetric(
            'test',
            ['v1' => TestKeys::ALICE_PUBLIC_V1],
            'v9',
            TestKeys::PREFIX,
        );
    }

    /**
     * @param class-string $class
     * @return list<class-string>
     */
    private function interfacesOf(string $class): array
    {
        return new ReflectionClass($class)->getInterfaceNames();
    }

    private function vault(string $activeKeyId = 'v1'): AnonymousAsymmetricEncryptor
    {
        return EncryptorFactory::createAnonymousAsymmetric(
            'vault',
            ['v1' => TestKeys::ALICE_SECRET_V1, 'v2' => TestKeys::ALICE_SECRET_V2],
            ['v1' => TestKeys::ALICE_PUBLIC_V1, 'v2' => TestKeys::ALICE_PUBLIC_V2],
            $activeKeyId,
            TestKeys::PREFIX,
        );
    }

    private function writeOnly(string $activeKeyId = 'v1'): WriteOnlyAnonymousAsymmetricEncryptor
    {
        return EncryptorFactory::createWriteOnlyAnonymousAsymmetric(
            'partner_inbox',
            ['v1' => TestKeys::ALICE_PUBLIC_V1, 'v2' => TestKeys::ALICE_PUBLIC_V2],
            $activeKeyId,
            TestKeys::PREFIX,
        );
    }
}
