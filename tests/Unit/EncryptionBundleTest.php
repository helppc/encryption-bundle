<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Unit;

use HelpPC\EncryptionBundle\Encryption\AdditionalDataDecryptor;
use HelpPC\EncryptionBundle\Encryption\AdditionalDataEncryptor;
use HelpPC\EncryptionBundle\Encryption\AnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\AsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\Decryptor;
use HelpPC\EncryptionBundle\Encryption\Encryptor;
use HelpPC\EncryptionBundle\Encryption\SymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\WriteOnlyAnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\EncryptionBundle;
use HelpPC\EncryptionBundle\EncryptionType;
use HelpPC\EncryptionBundle\Exception\InvalidEncryptionConfigurationException;
use HelpPC\EncryptionBundle\Tests\Fixture\TestKeys;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

use function sprintf;

#[CoversClass(EncryptionBundle::class)]
final class EncryptionBundleTest extends TestCase
{
    public function testEachGroupBecomesOneService(): void
    {
        $builder = $this->load([
            'groups' => [
                'default' => $this->symmetricGroup(),
                'vault' => $this->anonymousGroup(withSecretKey: true),
            ],
        ]);

        self::assertTrue($builder->hasDefinition('encryption.default'));
        self::assertTrue($builder->hasDefinition('encryption.vault'));
        self::assertSame(SymmetricEncryptor::class, $builder->getDefinition('encryption.default')->getClass());
        self::assertSame(
            AnonymousAsymmetricEncryptor::class,
            $builder->getDefinition('encryption.vault')->getClass(),
        );
    }

    public function testAnonymousGroupWithoutSecretKeysIsWriteOnly(): void
    {
        $builder = $this->load([
            'groups' => ['partner_inbox' => $this->anonymousGroup(withSecretKey: false)],
        ]);

        self::assertSame(
            WriteOnlyAnonymousAsymmetricEncryptor::class,
            $builder->getDefinition('encryption.partner_inbox')->getClass(),
        );
    }

    public function testWriteOnlyGroupGetsNoDecryptorAlias(): void
    {
        $builder = $this->load([
            'groups' => ['partner_inbox' => $this->anonymousGroup(withSecretKey: false)],
        ]);

        self::assertTrue($builder->hasAlias(sprintf('%s $partnerInbox', Encryptor::class)));
        self::assertFalse($builder->hasAlias(sprintf('%s $partnerInbox', Decryptor::class)));
        self::assertFalse($builder->hasAlias(Decryptor::class));
    }

    public function testGroupIsAddressableUnderBothItsSpellings(): void
    {
        $builder = $this->load([
            'groups' => ['partner_inbox' => $this->anonymousGroup(withSecretKey: false)],
        ]);

        self::assertTrue($builder->hasAlias(sprintf('%s $partner_inbox', Encryptor::class)));
        self::assertTrue($builder->hasAlias(sprintf('%s $partnerInbox', Encryptor::class)));
    }

    public function testAnonymousGroupsAreNotAliasedForAdditionalData(): void
    {
        $builder = $this->load([
            'groups' => ['vault' => $this->anonymousGroup(withSecretKey: true)],
        ]);

        self::assertTrue($builder->hasAlias(Decryptor::class));
        self::assertFalse($builder->hasAlias(AdditionalDataEncryptor::class));
        self::assertFalse($builder->hasAlias(AdditionalDataDecryptor::class));
    }

    public function testSymmetricGroupIsAliasedForEveryInterface(): void
    {
        $builder = $this->load(['groups' => ['default' => $this->symmetricGroup()]]);

        $interfaces = [
            Encryptor::class,
            Decryptor::class,
            AdditionalDataEncryptor::class,
            AdditionalDataDecryptor::class,
        ];

        foreach ($interfaces as $interface) {
            self::assertTrue($builder->hasAlias($interface), $interface . ' should resolve to the default group');
            self::assertSame('encryption.default', (string) $builder->getAlias($interface));
        }
    }

    public function testTypeCanBeGivenAsAnEnumCase(): void
    {
        $group = $this->anonymousGroup(withSecretKey: true);
        $group['type'] = EncryptionType::AnonymousAsymmetric;

        $builder = $this->load(['groups' => ['vault' => $group]]);

        self::assertSame(
            AnonymousAsymmetricEncryptor::class,
            $builder->getDefinition('encryption.vault')->getClass(),
        );
    }

    public function testTypeDefaultsToSymmetric(): void
    {
        $group = $this->symmetricGroup();
        unset($group['type']);

        $builder = $this->load(['groups' => ['default' => $group]]);

        self::assertSame(SymmetricEncryptor::class, $builder->getDefinition('encryption.default')->getClass());
    }

    public function testAsymmetricGroupUsesTheAuthenticatedEncryptor(): void
    {
        $builder = $this->load(['groups' => ['peer' => $this->asymmetricGroup()]]);

        self::assertSame(AsymmetricEncryptor::class, $builder->getDefinition('encryption.peer')->getClass());
    }

    public function testTheOnlyGroupBecomesTheDefaultWhateverItIsCalled(): void
    {
        $builder = $this->load(['groups' => ['addresses' => $this->symmetricGroup()]]);

        self::assertSame('encryption.addresses', (string) $builder->getAlias(Encryptor::class));
    }

    public function testGroupNamedDefaultWinsWithoutBeingDeclared(): void
    {
        $builder = $this->load([
            'groups' => [
                'addresses' => $this->symmetricGroup(),
                'default' => $this->symmetricGroup(),
            ],
        ]);

        self::assertSame('encryption.default', (string) $builder->getAlias(Encryptor::class));
    }

    public function testDefaultGroupCanBeChosenExplicitly(): void
    {
        $builder = $this->load([
            'default_group' => 'addresses',
            'groups' => [
                'addresses' => $this->symmetricGroup(),
                'vault' => $this->anonymousGroup(withSecretKey: true),
            ],
        ]);

        self::assertSame('encryption.addresses', (string) $builder->getAlias(Encryptor::class));
    }

    public function testSeveralGroupsWithoutADefaultAreRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        $this->load([
            'groups' => [
                'addresses' => $this->symmetricGroup(),
                'vault' => $this->anonymousGroup(withSecretKey: true),
            ],
        ]);
    }

    public function testUnknownDefaultGroupIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        $this->load([
            'default_group' => 'nope',
            'groups' => ['addresses' => $this->symmetricGroup()],
        ]);
    }

    /**
     * A group that can decrypt has to be able to decrypt what it wrote with its older keys too.
     */
    public function testAnonymousGroupWithSecretKeyOnSomeKeysOnlyIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        $this->load([
            'groups' => [
                'vault' => [
                    'type' => 'anonymous_asymmetric',
                    'key_prefix' => TestKeys::PREFIX,
                    'active_key' => 'v2',
                    'keys' => [
                        'v1' => ['public_key' => TestKeys::ALICE_PUBLIC_V1],
                        'v2' => [
                            'public_key' => TestKeys::ALICE_PUBLIC_V2,
                            'secret_key' => TestKeys::ALICE_SECRET_V2,
                        ],
                    ],
                ],
            ],
        ]);
    }

    public function testAsymmetricGroupWithoutASecretKeyIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        $this->load([
            'groups' => [
                'peer' => [
                    'type' => 'asymmetric',
                    'key_prefix' => TestKeys::PREFIX,
                    'active_key' => 'v1',
                    'keys' => ['v1' => ['public_key' => TestKeys::BOB_PUBLIC_V1]],
                ],
            ],
        ]);
    }

    public function testSymmetricGroupWithoutAKeyValueIsRejected(): void
    {
        $this->expectException(InvalidEncryptionConfigurationException::class);
        $this->load([
            'groups' => [
                'default' => [
                    'key_prefix' => TestKeys::PREFIX,
                    'active_key' => 'v1',
                    'keys' => ['v1' => ['public_key' => TestKeys::ALICE_PUBLIC_V1]],
                ],
            ],
        ]);
    }

    public function testUnknownEncryptionTypeIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->load([
            'groups' => [
                'default' => ['type' => 'rot13'] + $this->symmetricGroup(),
            ],
        ]);
    }

    public function testAGroupWithoutKeysIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->load([
            'groups' => [
                'default' => [
                    'key_prefix' => TestKeys::PREFIX,
                    'active_key' => 'v1',
                    'keys' => [],
                ],
            ],
        ]);
    }

    public function testConfigurationWithoutAnyGroupIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->load(['groups' => []]);
    }

    public function testTheKeyGenerationCommandIsRegistered(): void
    {
        $builder = $this->load(['groups' => ['default' => $this->symmetricGroup()]]);
        $definition = $builder->getDefinition('encryption.command.generate_key');

        self::assertTrue($definition->hasTag('console.command'));
    }

    /**
     * @return array<string, mixed>
     */
    private function symmetricGroup(): array
    {
        return [
            'key_prefix' => TestKeys::PREFIX,
            'active_key' => 'v2',
            'keys' => [
                'v1' => TestKeys::SYMMETRIC_V1,
                'v2' => TestKeys::SYMMETRIC_V2,
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function asymmetricGroup(): array
    {
        return [
            'type' => 'asymmetric',
            'key_prefix' => TestKeys::PREFIX,
            'active_key' => 'v1',
            'keys' => [
                'v1' => [
                    'secret_key' => TestKeys::ALICE_SECRET_V1,
                    'public_key' => TestKeys::BOB_PUBLIC_V1,
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function anonymousGroup(bool $withSecretKey): array
    {
        $key = ['public_key' => TestKeys::ALICE_PUBLIC_V1];
        if ($withSecretKey) {
            $key['secret_key'] = TestKeys::ALICE_SECRET_V1;
        }

        return [
            'type' => 'anonymous_asymmetric',
            'key_prefix' => TestKeys::PREFIX,
            'active_key' => 'v1',
            'keys' => ['v1' => $key],
        ];
    }

    /**
     * @param array<string, mixed> $config
     */
    private function load(array $config): ContainerBuilder
    {
        $builder = new ContainerBuilder();
        $extension = new EncryptionBundle()->getContainerExtension();
        self::assertNotNull($extension);
        $extension->load([$config], $builder);

        return $builder;
    }
}
