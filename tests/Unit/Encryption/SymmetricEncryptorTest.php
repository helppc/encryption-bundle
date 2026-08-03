<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Unit\Encryption;

use HelpPC\EncryptionBundle\Encryption\EncryptorFactory;
use HelpPC\EncryptionBundle\Encryption\SymmetricEncryptor;
use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use HelpPC\EncryptionBundle\Exception\InvalidEncryptionConfigurationException;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKeys;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function print_r;
use function str_contains;
use function substr;

#[CoversClass(SymmetricEncryptor::class)]
#[CoversClass(EncryptorFactory::class)]
final class SymmetricEncryptorTest extends TestCase
{
    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testRoundTrip(): void
    {
        $encryptor = $this->encryptor();
        $cipherText = $encryptor->encrypt('Ke Karlovu 2027/3');

        self::assertNotSame('Ke Karlovu 2027/3', $cipherText);
        self::assertSame('Ke Karlovu 2027/3', $encryptor->decrypt($cipherText));
    }

    /**
     * @throws EncryptionException
     */
    public function testEncryptingTheSameValueTwiceGivesDifferentCipherText(): void
    {
        $encryptor = $this->encryptor();

        self::assertNotSame($encryptor->encrypt('same'), $encryptor->encrypt('same'));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testAdditionalDataRoundTrip(): void
    {
        $encryptor = $this->encryptor();
        $cipherText = $encryptor->encryptWithAdditionalData('Ke Karlovu 2027/3', 'tenant-42');

        self::assertSame('Ke Karlovu 2027/3', $encryptor->decryptWithAdditionalData($cipherText, 'tenant-42'));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testDecryptingWithDifferentAdditionalDataFails(): void
    {
        $encryptor = $this->encryptor();
        $cipherText = $encryptor->encryptWithAdditionalData('Ke Karlovu 2027/3', 'tenant-42');

        $this->expectException(DecryptionException::class);
        $encryptor->decryptWithAdditionalData($cipherText, 'tenant-43');
    }

    /**
     * @throws EncryptionException
     */
    public function testAdditionalDataCannotBeEmpty(): void
    {
        $this->expectException(EncryptionException::class);
        $this->encryptor()->encryptWithAdditionalData('Ke Karlovu 2027/3', '');
    }

    /**
     * Empty additional data is refused on the way back too, rather than read as "no additional data"
     * and quietly failing authentication instead.
     *
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testAdditionalDataCannotBeEmptyWhenDecrypting(): void
    {
        $encryptor = $this->encryptor();
        $cipherText = $encryptor->encryptWithAdditionalData('Ke Karlovu 2027/3', 'tenant-42');

        $this->expectException(DecryptionException::class);
        $encryptor->decryptWithAdditionalData($cipherText, '');
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testValueEncryptedWithAdditionalDataCannotBeReadWithoutIt(): void
    {
        $encryptor = $this->encryptor();
        $cipherText = $encryptor->encryptWithAdditionalData('Ke Karlovu 2027/3', 'tenant-42');

        $this->expectException(DecryptionException::class);
        $encryptor->decrypt($cipherText);
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testOlderKeyStaysReadableAndIsReportedForReEncryption(): void
    {
        $writtenWithV1 = $this->encryptor('v1')->encrypt('Ke Karlovu 2027/3');
        $current = $this->encryptor('v2');

        self::assertSame('Ke Karlovu 2027/3', $current->decrypt($writtenWithV1));
        self::assertTrue($current->needsReEncryption($writtenWithV1));
        self::assertFalse($current->needsReEncryption($current->encrypt('Ke Karlovu 2027/3')));
    }

    /**
     * needsReEncryption() reads the envelope and nothing else, so an unknown key id is reported for
     * re-encryption instead of rejected. Only the decrypt() that a migration sweep runs next fails.
     *
     * @throws DecryptionException
     */
    public function testAnUnknownKeyIdIsReportedForReEncryptionRatherThanRejected(): void
    {
        $encryptor = $this->encryptor();

        self::assertTrue($encryptor->needsReEncryption('$v9$SymV1$abc'));
        self::assertTrue($encryptor->isEncrypted('$v9$SymV1$abc'));

        $this->expectException(DecryptionException::class);
        $encryptor->decrypt('$v9$SymV1$abc');
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testDecryptingWithAnUnconfiguredKeyIdFails(): void
    {
        $writtenWithV2 = $this->encryptor('v2')->encrypt('Ke Karlovu 2027/3');
        $onlyV1 = EncryptorFactory::createSymmetric(
            'test',
            ['v1' => TestKeys::SYMMETRIC_V1],
            'v1',
            TestKeys::PREFIX,
        );

        $this->expectException(DecryptionException::class);
        $onlyV1->decrypt($writtenWithV2);
    }

    /**
     * @throws DecryptionException
     */
    #[DataProvider('notCipherText')]
    public function testValuesThatAreNotCipherTextAreRejected(string $value): void
    {
        $encryptor = $this->encryptor();

        self::assertFalse($encryptor->isEncrypted($value));

        $this->expectException(DecryptionException::class);
        $encryptor->needsReEncryption($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function notCipherText(): iterable
    {
        yield 'plain text' => ['Ke Karlovu 2027/3'];
        yield 'empty' => [''];
        yield 'separator only' => ['$'];
        yield 'too few components' => ['$v1'];
        yield 'leading garbage' => ['garbage$v1$ciphertext'];
    }

    /**
     * @throws EncryptionException
     */
    public function testCipherTextIsRecognised(): void
    {
        $encryptor = $this->encryptor();

        self::assertTrue($encryptor->isEncrypted($encryptor->encrypt('Ke Karlovu 2027/3')));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testTruncatedCipherTextFailsToDecrypt(): void
    {
        $encryptor = $this->encryptor();
        $cipherText = $encryptor->encrypt('Ke Karlovu 2027/3');

        $this->expectException(DecryptionException::class);
        $encryptor->decrypt(substr($cipherText, 0, -4));
    }

    public function testKeyDoesNotLeakIntoDebugOutput(): void
    {
        $dump = print_r($this->encryptor(), true);

        self::assertFalse(str_contains($dump, substr(TestKeys::SYMMETRIC_V1, 5)));
        self::assertFalse(str_contains($dump, substr(TestKeys::SYMMETRIC_V2, 5)));
    }

    public function testMisconfiguredGroupIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        EncryptorFactory::createSymmetric(
            'test',
            ['v1' => TestKeys::SYMMETRIC_V1],
            'v9',
            TestKeys::PREFIX,
        );
    }

    public function testKeyWithTheWrongPrefixIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        EncryptorFactory::createSymmetric(
            'test',
            ['v1' => TestKeys::SYMMETRIC_V1],
            'v1',
            'other',
        );
    }

    private function encryptor(string $activeKeyId = 'v2'): SymmetricEncryptor
    {
        return EncryptorFactory::createSymmetric(
            'test',
            ['v1' => TestKeys::SYMMETRIC_V1, 'v2' => TestKeys::SYMMETRIC_V2],
            $activeKeyId,
            TestKeys::PREFIX,
        );
    }
}
