<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle;

use HelpPC\EncryptionBundle\Command\GenerateEncryptionKeyCommand;
use HelpPC\EncryptionBundle\DependencyInjection\EncryptionType;
use HelpPC\EncryptionBundle\Encryption\AdditionalDataDecryptor;
use HelpPC\EncryptionBundle\Encryption\AdditionalDataEncryptor;
use HelpPC\EncryptionBundle\Encryption\AnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\AsymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\Decryptor;
use HelpPC\EncryptionBundle\Encryption\Encryptor;
use HelpPC\EncryptionBundle\Encryption\EncryptorFactory;
use HelpPC\EncryptionBundle\Encryption\SymmetricEncryptor;
use HelpPC\EncryptionBundle\Encryption\WriteOnlyAnonymousAsymmetricEncryptor;
use HelpPC\EncryptionBundle\Exception\InvalidEncryptionConfigurationException;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

use function array_key_exists;
use function array_key_first;
use function count;
use function is_array;
use function is_string;
use function lcfirst;
use function sprintf;
use function str_replace;
use function ucwords;

/**
 * Each configured group becomes one service, `encryption.<group>`, implementing only the
 * interfaces its encryption type can honour.
 */
final class EncryptionBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('default_group')
                    ->defaultNull()
                    ->info('Group wired to the bare interfaces. Defaults to the only group, or to one named "default".')
                ->end()
                ->arrayNode('groups')
                    ->useAttributeAsKey('name')
                    ->requiresAtLeastOneElement()
                    ->arrayPrototype()
                        ->children()
                            ->enumNode('type')
                                ->values([
                                    EncryptionType::Symmetric->value,
                                    EncryptionType::Asymmetric->value,
                                    EncryptionType::AnonymousAsymmetric->value,
                                ])
                                ->defaultValue(EncryptionType::Symmetric->value)
                            ->end()
                            ->scalarNode('key_prefix')
                                ->isRequired()
                                ->cannotBeEmpty()
                                ->info('Prefix every key of this group carries, making a leak identifiable.')
                            ->end()
                            ->scalarNode('active_key')
                                ->isRequired()
                                ->cannotBeEmpty()
                                ->info('Key id for new values. The others stay configured so old values stay readable.')
                            ->end()
                            ->arrayNode('keys')
                                ->useAttributeAsKey('id')
                                ->requiresAtLeastOneElement()
                                ->arrayPrototype()
                                    ->beforeNormalization()
                                        ->ifString()
                                        ->then(static fn (string $value): array => ['key' => $value])
                                    ->end()
                                    ->children()
                                        ->scalarNode('key')->defaultNull()->end()
                                        ->scalarNode('public_key')->defaultNull()->end()
                                        ->scalarNode('secret_key')->defaultNull()->end()
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param array<mixed, mixed> $config
     */
    public function loadExtension(
        array $config,
        ContainerConfigurator $container,
        ContainerBuilder $builder,
    ): void {
        $groups = $config['groups'] ?? [];
        if (!is_array($groups) || $groups === []) {
            throw new InvalidEncryptionConfigurationException('At least one encryption group must be configured.');
        }

        /** @var array<string, string> $serviceIds group name => service id */
        $serviceIds = [];
        foreach ($groups as $name => $group) {
            if (!is_string($name) || !is_array($group)) {
                throw new InvalidEncryptionConfigurationException(
                    'Encryption groups must be a map of name => settings.',
                );
            }
            $serviceId = sprintf('encryption.%s', $name);
            $builder->setDefinition($serviceId, $this->createDefinition($name, $group));
            $serviceIds[$name] = $serviceId;
        }

        $this->registerAliases($builder, $groups, $serviceIds, $this->resolveDefaultGroup($config, $serviceIds));
        $this->registerCommand($builder);
    }

    /**
     * @param array<mixed, mixed> $group
     */
    private function createDefinition(string $name, array $group): Definition
    {
        $type = EncryptionType::from($this->stringValue($name, $group, 'type'));
        $keyPrefix = $this->stringValue($name, $group, 'key_prefix');
        $activeKey = $this->stringValue($name, $group, 'active_key');
        $keys = $group['keys'] ?? null;
        if (!is_array($keys) || $keys === []) {
            throw new InvalidEncryptionConfigurationException(
                sprintf('Encryption group "%s" has no keys.', $name),
            );
        }

        return match ($type) {
            EncryptionType::Symmetric => $this->symmetricDefinition($name, $keys, $activeKey, $keyPrefix),
            EncryptionType::Asymmetric => $this->asymmetricDefinition($name, $keys, $activeKey, $keyPrefix),
            EncryptionType::AnonymousAsymmetric => $this->anonymousDefinition($name, $keys, $activeKey, $keyPrefix),
        };
    }

    /**
     * @param array<array-key, mixed> $keys
     */
    private function symmetricDefinition(string $name, array $keys, string $activeKey, string $keyPrefix): Definition
    {
        $material = [];
        foreach ($keys as $id => $key) {
            $material[(string) $id] = $this->keyComponent($name, (string) $id, $key, 'key');
        }

        return $this->factoryDefinition(
            SymmetricEncryptor::class,
            'createSymmetric',
            [$name, $material, $activeKey, $keyPrefix],
        );
    }

    /**
     * @param array<array-key, mixed> $keys
     */
    private function asymmetricDefinition(string $name, array $keys, string $activeKey, string $keyPrefix): Definition
    {
        $secretKeys = [];
        $publicKeys = [];
        foreach ($keys as $id => $key) {
            $id = (string) $id;
            $secretKeys[$id] = $this->keyComponent($name, $id, $key, 'secret_key');
            $publicKeys[$id] = $this->keyComponent($name, $id, $key, 'public_key');
        }

        return $this->factoryDefinition(
            AsymmetricEncryptor::class,
            'createAsymmetric',
            [$name, $secretKeys, $publicKeys, $activeKey, $keyPrefix],
        );
    }

    /**
     * @param array<array-key, mixed> $keys
     */
    private function anonymousDefinition(string $name, array $keys, string $activeKey, string $keyPrefix): Definition
    {
        $secretKeys = [];
        $publicKeys = [];
        foreach ($keys as $id => $key) {
            $id = (string) $id;
            $publicKeys[$id] = $this->keyComponent($name, $id, $key, 'public_key');
            $secret = is_array($key) ? ($key['secret_key'] ?? null) : null;
            if (is_string($secret) && $secret !== '') {
                $secretKeys[$id] = $secret;
            }
        }

        if ($secretKeys !== [] && count($secretKeys) !== count($publicKeys)) {
            throw new InvalidEncryptionConfigurationException(sprintf(
                'Encryption group "%s" defines a secret key for some of its keys but not all of them. '
                . 'Either every key has one, and the group can read everything it ever wrote, or none has '
                . 'and the group is write-only.',
                $name,
            ));
        }

        if ($secretKeys === []) {
            return $this->factoryDefinition(
                WriteOnlyAnonymousAsymmetricEncryptor::class,
                'createWriteOnlyAnonymousAsymmetric',
                [$name, $publicKeys, $activeKey, $keyPrefix],
            );
        }

        return $this->factoryDefinition(
            AnonymousAsymmetricEncryptor::class,
            'createAnonymousAsymmetric',
            [$name, $secretKeys, $publicKeys, $activeKey, $keyPrefix],
        );
    }

    /**
     * @param class-string $class
     * @param array<int, mixed> $arguments
     */
    private function factoryDefinition(string $class, string $method, array $arguments): Definition
    {
        $definition = new Definition($class);
        $definition->setFactory([EncryptorFactory::class, $method]);
        $definition->setArguments($arguments);

        return $definition;
    }

    /**
     * @param array<string, mixed> $groups
     * @param array<string, string> $serviceIds
     */
    private function registerAliases(
        ContainerBuilder $builder,
        array $groups,
        array $serviceIds,
        string $defaultGroup,
    ): void {
        foreach ($serviceIds as $name => $serviceId) {
            $group = $groups[$name];
            if (!is_array($group)) {
                continue;
            }
            foreach ($this->interfacesFor($builder->getDefinition($serviceId)) as $interface) {
                foreach ($this->targetNames($name) as $targetName) {
                    $builder->setAlias(sprintf('%s $%s', $interface, $targetName), $serviceId);
                }
                if ($name !== $defaultGroup) {
                    continue;
                }
                $builder->setAlias($interface, $serviceId)->setPublic(true);
            }
        }
    }

    /**
     * @return list<class-string>
     */
    private function interfacesFor(Definition $definition): array
    {
        return match ($definition->getClass()) {
            SymmetricEncryptor::class, AsymmetricEncryptor::class => [
                Encryptor::class,
                Decryptor::class,
                AdditionalDataEncryptor::class,
                AdditionalDataDecryptor::class,
            ],
            AnonymousAsymmetricEncryptor::class => [Encryptor::class, Decryptor::class],
            default => [Encryptor::class],
        };
    }

    /**
     * Both spellings, so partner_inbox answers to #[Target('partner_inbox')] and
     * #[Target('partnerInbox')] alike.
     *
     * @return list<string>
     */
    private function targetNames(string $name): array
    {
        $camelCase = lcfirst(str_replace(' ', '', ucwords(str_replace(['_', '-'], ' ', $name))));

        return $camelCase === $name ? [$name] : [$name, $camelCase];
    }

    /**
     * @param array<mixed, mixed> $config
     * @param array<string, string> $serviceIds
     */
    private function resolveDefaultGroup(array $config, array $serviceIds): string
    {
        $configured = $config['default_group'] ?? null;
        if (is_string($configured) && $configured !== '') {
            if (!array_key_exists($configured, $serviceIds)) {
                throw new InvalidEncryptionConfigurationException(sprintf(
                    'Default encryption group "%s" is not configured.',
                    $configured,
                ));
            }

            return $configured;
        }

        if (array_key_exists('default', $serviceIds)) {
            return 'default';
        }

        if (count($serviceIds) === 1) {
            return array_key_first($serviceIds);
        }

        throw new InvalidEncryptionConfigurationException(
            'With more than one encryption group, "default_group" has to say which one the bare '
            . 'interfaces resolve to, or one of the groups has to be named "default".',
        );
    }

    /**
     * @param array<mixed, mixed> $group
     */
    private function stringValue(string $name, array $group, string $key): string
    {
        $value = $group[$key] ?? null;
        if (!is_string($value) || $value === '') {
            throw new InvalidEncryptionConfigurationException(sprintf(
                'Encryption group "%s" is missing "%s".',
                $name,
                $key,
            ));
        }

        return $value;
    }

    private function keyComponent(string $group, string $id, mixed $key, string $component): string
    {
        $value = is_array($key) ? ($key[$component] ?? null) : null;
        if (!is_string($value) || $value === '') {
            throw new InvalidEncryptionConfigurationException(sprintf(
                'Key "%s" of encryption group "%s" is missing "%s".',
                $id,
                $group,
                $component,
            ));
        }

        return $value;
    }

    private function registerCommand(ContainerBuilder $builder): void
    {
        $definition = new Definition(GenerateEncryptionKeyCommand::class);
        $definition->addTag('console.command');
        $builder->setDefinition('encryption.command.generate_key', $definition);
    }
}
