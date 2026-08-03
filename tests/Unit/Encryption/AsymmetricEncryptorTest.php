<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Unit\Encryption;

use HelpPC\EncryptionBundle\Encryption\AsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\EncryptorFactory;
use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use HelpPC\EncryptionBundle\Exception\InvalidEncryptionConfigurationException;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKeys;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function print_r;
use function str_contains;
use function substr;

/**
 * Both parties hold a key pair: our secret key and the other party's public key. Alice and Bob
 * here are the two ends of the same channel.
 */
#[CoversClass(AsymmetricEncryptor::class)]
#[CoversClass(EncryptorFactory::class)]
final class AsymmetricEncryptorTest extends TestCase
{
    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testEitherPartyCanReadWhatTheOtherWrote(): void
    {
        $fromAlice = $this->alice()->encrypt('Ke Karlovu 2027/3');
        self::assertSame('Ke Karlovu 2027/3', $this->bob()->decrypt($fromAlice));

        $fromBob = $this->bob()->encrypt('Malostranské náměstí 25');
        self::assertSame('Malostranské náměstí 25', $this->alice()->decrypt($fromBob));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testSenderCanReadTheirOwnValue(): void
    {
        $alice = $this->alice();

        self::assertSame('Ke Karlovu 2027/3', $alice->decrypt($alice->encrypt('Ke Karlovu 2027/3')));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testAdditionalDataRoundTrip(): void
    {
        $cipherText = $this->alice()->encryptWithAdditionalData('Ke Karlovu 2027/3', 'tenant-42');

        self::assertSame('Ke Karlovu 2027/3', $this->bob()->decryptWithAdditionalData($cipherText, 'tenant-42'));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testDecryptingWithDifferentAdditionalDataFails(): void
    {
        $cipherText = $this->alice()->encryptWithAdditionalData('Ke Karlovu 2027/3', 'tenant-42');

        $this->expectException(DecryptionException::class);
        $this->bob()->decryptWithAdditionalData($cipherText, 'tenant-43');
    }

    /**
     * @throws EncryptionException
     */
    public function testAdditionalDataCannotBeEmpty(): void
    {
        $this->expectException(EncryptionException::class);
        $this->alice()->encryptWithAdditionalData('Ke Karlovu 2027/3', '');
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testAThirdPartyCannotRead(): void
    {
        $fromAlice = $this->alice()->encrypt('Ke Karlovu 2027/3');
        $stranger = EncryptorFactory::createAsymmetric(
            'stranger',
            ['v1' => TestKeys::BOB_SECRET_V2],
            ['v1' => TestKeys::ALICE_PUBLIC_V2],
            'v1',
            TestKeys::PREFIX,
        );

        $this->expectException(DecryptionException::class);
        $stranger->decrypt($fromAlice);
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testOlderKeyStaysReadableAndIsReportedForReEncryption(): void
    {
        $writtenWithV1 = $this->alice('v1')->encrypt('Ke Karlovu 2027/3');
        $current = $this->alice('v2');

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
        $alice = $this->alice();

        self::assertTrue($alice->needsReEncryption('$v9$AuthV1$abc'));
        self::assertTrue($alice->isEncrypted('$v9$AuthV1$abc'));

        $this->expectException(DecryptionException::class);
        $alice->decrypt('$v9$AuthV1$abc');
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testPlainTextIsNotMistakenForCipherText(): void
    {
        $alice = $this->alice();

        self::assertFalse($alice->isEncrypted('Ke Karlovu 2027/3'));
        self::assertTrue($alice->isEncrypted($alice->encrypt('Ke Karlovu 2027/3')));

        $this->expectException(DecryptionException::class);
        $alice->needsReEncryption('Ke Karlovu 2027/3');
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testTruncatedCipherTextFailsToDecrypt(): void
    {
        $cipherText = $this->alice()->encrypt('Ke Karlovu 2027/3');

        $this->expectException(DecryptionException::class);
        $this->bob()->decrypt(substr($cipherText, 0, -4));
    }

    public function testKeyDoesNotLeakIntoDebugOutput(): void
    {
        $dump = print_r($this->alice(), true);

        self::assertFalse(str_contains($dump, substr(TestKeys::ALICE_SECRET_V1, 12)));
        self::assertFalse(str_contains($dump, substr(TestKeys::ALICE_SECRET_V2, 12)));
    }

    public function testAKeyPairMissingOneHalfIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        EncryptorFactory::createAsymmetric(
            'test',
            ['v1' => TestKeys::ALICE_SECRET_V1, 'v2' => TestKeys::ALICE_SECRET_V2],
            ['v1' => TestKeys::BOB_PUBLIC_V1],
            'v1',
            TestKeys::PREFIX,
        );
    }

    public function testASecretKeyConfiguredAsPublicIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        EncryptorFactory::createAsymmetric(
            'test',
            ['v1' => TestKeys::ALICE_SECRET_V1],
            ['v1' => TestKeys::BOB_SECRET_V1],
            'v1',
            TestKeys::PREFIX,
        );
    }

    public function testActiveKeyNeedsOurSecretKey(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        EncryptorFactory::createAsymmetric(
            'test',
            ['v1' => TestKeys::ALICE_SECRET_V1],
            ['v1' => TestKeys::BOB_PUBLIC_V1],
            'v9',
            TestKeys::PREFIX,
        );
    }

    private function alice(string $activeKeyId = 'v1'): AsymmetricEncryptor
    {
        return EncryptorFactory::createAsymmetric(
            'alice',
            ['v1' => TestKeys::ALICE_SECRET_V1, 'v2' => TestKeys::ALICE_SECRET_V2],
            ['v1' => TestKeys::BOB_PUBLIC_V1, 'v2' => TestKeys::BOB_PUBLIC_V2],
            $activeKeyId,
            TestKeys::PREFIX,
        );
    }

    private function bob(string $activeKeyId = 'v1'): AsymmetricEncryptor
    {
        return EncryptorFactory::createAsymmetric(
            'bob',
            ['v1' => TestKeys::BOB_SECRET_V1, 'v2' => TestKeys::BOB_SECRET_V2],
            ['v1' => TestKeys::ALICE_PUBLIC_V1, 'v2' => TestKeys::ALICE_PUBLIC_V2],
            $activeKeyId,
            TestKeys::PREFIX,
        );
    }
}
