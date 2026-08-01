<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Command;

use Random\RandomException;
use SodiumException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

use function is_string;
use function sodium_bin2hex;
use function sodium_crypto_box_keypair;
use function sodium_crypto_box_publickey;
use function sodium_crypto_box_secretkey;
use function sprintf;
use function str_contains;

#[AsCommand(
    name: 'encryption:generate-key',
    description: 'Generates a key or a key pair for an encryption group',
)]
final class GenerateEncryptionKeyCommand extends Command
{
    /** Spelled out because the enum defining these upstream is marked @internal. */
    private const string ROLE_SECRET = 'secret';

    private const string ROLE_PUBLIC = 'public';

    private const string PREFIX_SEPARATOR = '_';

    protected function configure(): void
    {
        $this
            ->addOption('symmetric', null, InputOption::VALUE_NONE, 'Generate a symmetric key')
            ->addOption('asymmetric', null, InputOption::VALUE_NONE, 'Generate an asymmetric key pair')
            ->addOption(
                'prefix',
                'p',
                InputOption::VALUE_REQUIRED,
                'Prefix the key carries, usually an initialism of its purpose'
                . ' (for example "adek" for address data encryption key)',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $symmetric = $input->getOption('symmetric') === true;
        $asymmetric = $input->getOption('asymmetric') === true;
        if ($symmetric === $asymmetric) {
            $io->error('Pass exactly one of --symmetric or --asymmetric.');

            return Command::INVALID;
        }

        $prefix = $input->getOption('prefix');
        if (!is_string($prefix) || $prefix === '') {
            $io->error('The --prefix option is required.');

            return Command::INVALID;
        }
        if (str_contains($prefix, self::PREFIX_SEPARATOR)) {
            $io->error(sprintf(
                'The prefix must not contain "%s", it separates the prefix from the key itself.',
                self::PREFIX_SEPARATOR,
            ));

            return Command::INVALID;
        }

        try {
            $symmetric ? $this->writeSymmetricKey($io, $prefix) : $this->writeKeyPair($io, $prefix);
        } catch (RandomException | SodiumException $exception) {
            $io->error(sprintf('Could not generate the key: %s', $exception->getMessage()));

            return Command::FAILURE;
        }

        $io->warning(
            'Store the value in .env.local or your secrets manager, not in a YAML file — a key written '
            . 'literally into configuration ends up in plain text in the compiled container under var/cache/.',
        );

        return Command::SUCCESS;
    }

    /**
     * @throws RandomException
     * @throws SodiumException
     */
    private function writeSymmetricKey(SymfonyStyle $io, string $prefix): void
    {
        $key = random_bytes(SODIUM_CRYPTO_STREAM_KEYBYTES);
        $io->writeln(sprintf('%s%s%s', $prefix, self::PREFIX_SEPARATOR, sodium_bin2hex($key)));
    }

    /**
     * @throws SodiumException
     */
    private function writeKeyPair(SymfonyStyle $io, string $prefix): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $secretKey = sodium_crypto_box_secretkey($keyPair);

        $io->definitionList(
            ['public_key' => $this->formatAsymmetricKey($prefix, self::ROLE_PUBLIC, $publicKey)],
            ['secret_key' => $this->formatAsymmetricKey($prefix, self::ROLE_SECRET, $secretKey)],
        );
    }

    /**
     * @throws SodiumException
     */
    private function formatAsymmetricKey(string $prefix, string $role, string $key): string
    {
        return sprintf(
            '%s%s%s%s%s',
            $prefix,
            self::PREFIX_SEPARATOR,
            $role,
            self::PREFIX_SEPARATOR,
            sodium_bin2hex($key),
        );
    }
}
