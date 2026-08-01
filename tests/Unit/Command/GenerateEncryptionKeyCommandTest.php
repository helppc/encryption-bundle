<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Unit\Command;

use HelpPC\EncryptionBundle\Command\GenerateEncryptionKeyCommand;
use HelpPC\EncryptionBundle\Encryption\EncryptorFactory;
use HelpPC\EncryptionBundle\Exception\DecryptionException;
use HelpPC\EncryptionBundle\Exception\EncryptionException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

use function preg_match;

/**
 * The command exists to emit values spaze/encryption accepts, so every test here feeds what it
 * printed straight back into the library.
 */
#[CoversClass(GenerateEncryptionKeyCommand::class)]
final class GenerateEncryptionKeyCommandTest extends TestCase
{
    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testSymmetricKeyIsAcceptedByTheLibrary(): void
    {
        $tester = $this->runCommand(['--symmetric' => true, '--prefix' => 'adek']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $key = $this->capture('/^(adek_[0-9a-f]{64})$/m', $tester->getDisplay());

        $encryptor = EncryptorFactory::createSymmetric('generated', ['v1' => $key], 'v1', 'adek');
        self::assertSame('Ke Karlovu 2027/3', $encryptor->decrypt($encryptor->encrypt('Ke Karlovu 2027/3')));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testKeyPairIsAcceptedByTheLibrary(): void
    {
        $tester = $this->runCommand(['--asymmetric' => true, '--prefix' => 'vault']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $display = $tester->getDisplay();
        $publicKey = $this->capture('/(vault_public_[0-9a-f]{64})/', $display);
        $secretKey = $this->capture('/(vault_secret_[0-9a-f]{64})/', $display);

        $encryptor = EncryptorFactory::createAnonymousAsymmetric(
            'generated',
            ['v1' => $secretKey],
            ['v1' => $publicKey],
            'v1',
            'vault',
        );
        self::assertSame('Ke Karlovu 2027/3', $encryptor->decrypt($encryptor->encrypt('Ke Karlovu 2027/3')));
    }

    /**
     * @throws DecryptionException
     * @throws EncryptionException
     */
    public function testGeneratedKeyPairAlsoWorksForTwoPartyEncryption(): void
    {
        $alice = $this->generateKeyPair('peer');
        $bob = $this->generateKeyPair('peer');

        $fromAlice = EncryptorFactory::createAsymmetric(
            'alice',
            ['v1' => $alice['secret']],
            ['v1' => $bob['public']],
            'v1',
            'peer',
        )->encrypt('Ke Karlovu 2027/3');

        $decrypted = EncryptorFactory::createAsymmetric(
            'bob',
            ['v1' => $bob['secret']],
            ['v1' => $alice['public']],
            'v1',
            'peer',
        )->decrypt($fromAlice);

        self::assertSame('Ke Karlovu 2027/3', $decrypted);
    }

    public function testTwoRunsNeverGiveTheSameKey(): void
    {
        $options = ['--symmetric' => true, '--prefix' => 'adek'];
        $first = $this->capture('/^(adek_[0-9a-f]{64})$/m', $this->runCommand($options)->getDisplay());
        $second = $this->capture('/^(adek_[0-9a-f]{64})$/m', $this->runCommand($options)->getDisplay());

        self::assertNotSame($first, $second);
    }

    public function testExactlyOneKindHasToBeRequested(): void
    {
        self::assertSame(Command::INVALID, $this->runCommand(['--prefix' => 'adek'])->getStatusCode());
        self::assertSame(
            Command::INVALID,
            $this->runCommand(['--symmetric' => true, '--asymmetric' => true, '--prefix' => 'adek'])->getStatusCode(),
        );
    }

    public function testPrefixIsRequired(): void
    {
        self::assertSame(Command::INVALID, $this->runCommand(['--symmetric' => true])->getStatusCode());
    }

    public function testPrefixCannotContainTheSeparator(): void
    {
        $tester = $this->runCommand(['--symmetric' => true, '--prefix' => 'ad_ek']);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
    }

    /**
     * @return array{secret: string, public: string}
     */
    private function generateKeyPair(string $prefix): array
    {
        $display = $this->runCommand(['--asymmetric' => true, '--prefix' => $prefix])->getDisplay();

        return [
            'secret' => $this->capture('/(' . $prefix . '_secret_[0-9a-f]{64})/', $display),
            'public' => $this->capture('/(' . $prefix . '_public_[0-9a-f]{64})/', $display),
        ];
    }

    private function capture(string $pattern, string $subject): string
    {
        $matched = preg_match($pattern, $subject, $matches);
        self::assertSame(1, $matched, 'The command did not print a key matching ' . $pattern);

        return $matches[1];
    }

    /**
     * @param array<string, bool|string> $input
     */
    private function runCommand(array $input): CommandTester
    {
        $tester = new CommandTester(new GenerateEncryptionKeyCommand());
        $tester->execute($input);

        return $tester;
    }
}
