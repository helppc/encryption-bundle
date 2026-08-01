<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php80\Rector\Class_\ClassPropertyAssignToConstructorPromotionRector;

return RectorConfig::configure()
    ->withPHPStanConfigs([__DIR__ . '/phpstan.neon'])
    ->withPaths([
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    ->withSkip([
        ClassPropertyAssignToConstructorPromotionRector::class
    ])
    ->withComposerBased(symfony: true, phpunit: true)
    ->withAttributesSets(symfony: true, phpunit: true)
    // LevelSetList is deprecated in Rector 2; withPhpSets() takes the target version from composer.json
    ->withPhpSets()
    ->withImportNames();
