<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Fixture;

use Exception;
use HelpPC\EncryptionBundle\EncryptionBundle;
use Override;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\HttpKernel\Kernel;

use function md5;
use function serialize;
use function sys_get_temp_dir;

final class TestKernel extends Kernel
{
    /**
     * @param array<string, mixed>|string $encryptionConfig an inline configuration array, or the
     *                                                      path to a configuration file to load
     * @param list<class-string> $consumers services autowired against the bundle's interfaces
     */
    public function __construct(
        private readonly array|string $encryptionConfig,
        private readonly array $consumers = [],
    ) {
        // Debug mode registers Symfony's error handler and never removes it, which PHPUnit reports
        // as a risky test.
        parent::__construct('test', false);
    }

    #[Override]
    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new EncryptionBundle();
    }

    /**
     * @throws Exception
     */
    #[Override]
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'secret' => 'test',
                'http_method_override' => false,
                'php_errors' => ['log' => false, 'throw' => false],
            ]);

            if (is_array($this->encryptionConfig)) {
                $container->loadFromExtension('encryption', $this->encryptionConfig);
            }

            foreach ($this->consumers as $consumer) {
                $definition = new Definition($consumer);
                $definition->setAutowired(true);
                $definition->setPublic(true);
                $container->setDefinition($consumer, $definition);
            }
        });

        if (is_string($this->encryptionConfig)) {
            $loader->load($this->encryptionConfig);
        }
    }

    #[Override]
    public function getCacheDir(): string
    {
        $fingerprint = md5(serialize([$this->encryptionConfig, $this->consumers]));

        return sys_get_temp_dir() . '/helppc-encryption-bundle/' . $fingerprint;
    }

    #[Override]
    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }
}
