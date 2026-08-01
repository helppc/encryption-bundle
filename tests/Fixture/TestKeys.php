<?php

declare(strict_types=1);

namespace HelpPC\EncryptionBundle\Tests\Fixture;

/**
 * Public test vectors, they protect nothing. Each Alice pair matches — anonymous groups verify
 * that a configured public key belongs to the secret key next to it.
 */
final class TestKeys
{
    public const string PREFIX = 'test';

    public const string SYMMETRIC_V1 = 'test_4a64fbfac36c180e6a243e689ae3dc13f14fb6e7ecda674098f47a9620338ede';

    public const string SYMMETRIC_V2 = 'test_4ec1e86ccc967d1700cc176ac204bdaadf302b32f7fdc6898d0d87de7a19008f';

    public const string ALICE_SECRET_V1
        = 'test_secret_c4984023b115d3e61e9b7a2facf1cb1ada207e7d8198f2406f6513d59ba5bd4b';

    public const string ALICE_PUBLIC_V1
        = 'test_public_801bcc274b11ae5fd958f1331e502dd838c5aad07e3c9893caafc14a9ea3f159';

    public const string ALICE_SECRET_V2
        = 'test_secret_d10e888a86b4e2ce5b0b0c451b5712bb833d8d3e15b8c3bc9108c286c37e2335';

    public const string ALICE_PUBLIC_V2
        = 'test_public_c0fd14072ca26723ad7bc8034f83ac51870ce70c5409f442f10edab433ab2406';

    public const string BOB_SECRET_V1
        = 'test_secret_c90c46514abe6e45cb0244e1a2645a522c8ad7849f368c2b98e1890fee1a17ab';

    public const string BOB_PUBLIC_V1
        = 'test_public_0716b4b648c02e92f70dfde7454af15977534a7eb0a15db5155630f62865a96a';

    public const string BOB_SECRET_V2
        = 'test_secret_61ecbed904ba3145a257c4e7c199a1e97e15b3808b6f44b9828a3125a50ca326';

    public const string BOB_PUBLIC_V2
        = 'test_public_2bd657de0311e162377d49dce133662e35205175b52cb7c91a50e8d290182064';
}
