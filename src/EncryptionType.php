<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle;

enum EncryptionType: string
{
    case Symmetric = 'symmetric';

    case Asymmetric = 'asymmetric';

    case AnonymousAsymmetric = 'anonymous_asymmetric';
}
