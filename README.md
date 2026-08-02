# EncryptionBundle

Symfony bundle exposing a typed encryption facade over
[`spaze/encryption`](https://github.com/spaze/encryption), which uses
[Halite](https://github.com/paragonie/halite) on top of [libsodium](https://php.net/sodium).

The bundle implements no cryptography of its own. It contributes configuration, dependency
injection, key rotation ergonomics, and interfaces narrow enough that a misconfigured group fails
when the container is compiled rather than at runtime.

## Requirements

- PHP >= 8.4
- `ext-sodium`
- Symfony 8

## Installation

```bash
composer config minimum-stability dev
composer config prefer-stable true
composer require helppc/encryption-bundle
```

> The two `config` lines are needed, and `composer require` alone fails without them.
> `spaze/encryption` is required as `dev-main`: its asymmetric classes are merged upstream but not
> tagged yet, the latest tag `v2.3.2` ships only `SymmetricKeyEncryption`. `prefer-stable` keeps
> every other dependency on its stable release. Both lines go away once a suitable tag exists.

Register the bundle in `config/bundles.php`:

```php
return [
    // ...
    HelpPC\EncryptionBundle\EncryptionBundle::class => ['all' => true],
];
```

## Generating keys

```console
$ bin/console encryption:generate-key --symmetric --prefix=adek
adek_3bf4c484daf46ccf286e25a67073b143870879cc770f85a6cdadcd19839bf60f

$ bin/console encryption:generate-key --asymmetric --prefix=vault
  public_key   vault_public_a7dcfc9a8f692ec1cf82fcbc1c27781a36c709c6eb1f75be1f8d1ed31de1550f
  secret_key   vault_secret_f6677e62a1ce2ecc6dc46364941f23b14a75553ba1c2e0af8d9cfacf8e0876eb
```

The prefix is free-form and makes a leaked credential identifiable — usually an initialism of its
purpose, `adek` for *address data encryption key*. It must not contain `_`, which separates the
prefix from the key.

Put the values in `.env.local` and reference them with `%env()%`. A key written literally into a
YAML file ends up in plain text in the compiled container under `var/cache/`, which leaks into
backups, deploy artifacts and debug tarballs.

## Configuration

```yaml
# config/packages/encryption.yaml
encryption:
    # Optional. Defaults to the only configured group, or to one named "default".
    default_group: default

    groups:
        default:
            type: symmetric          # the default, can be omitted
            key_prefix: adek
            active_key: v2
            keys:
                v1: '%env(ENCRYPTION_KEY_V1)%'    # scalar shorthand for { key: ... }
                v2: '%env(ENCRYPTION_KEY_V2)%'

        partner_inbox:               # write-only: can encrypt, can never decrypt
            type: anonymous_asymmetric
            key_prefix: partner
            active_key: v1
            keys:
                v1:
                    public_key: '%env(PARTNER_PUBLIC_KEY)%'

        vault:                       # sealed boxes, readable
            type: anonymous_asymmetric
            key_prefix: vault
            active_key: v1
            keys:
                v1:
                    public_key: '%env(VAULT_PUBLIC_KEY)%'
                    secret_key: '%env(VAULT_SECRET_KEY)%'

        peer:                        # two-party, supports additional data
            type: asymmetric
            key_prefix: peer
            active_key: v1
            keys:
                v1:
                    public_key: '%env(PEER_PUBLIC_KEY)%'    # the other party's
                    secret_key: '%env(PEER_SECRET_KEY)%'    # yours
```

Each group becomes one service, `encryption.<group>`.

### Encryption types

| `type` | `EncryptionType` case | Who can encrypt | Who can decrypt | Additional data | Can be write-only |
|---|---|---|---|---|---|
| `symmetric` (default) | `Symmetric` | anyone with the key | anyone with the key | yes | no |
| `asymmetric` | `Asymmetric` | holder of the key pair | the other party, and you | yes | no |
| `anonymous_asymmetric` | `AnonymousAsymmetric` | anyone with the public key | holder of the secret key | no | yes |

For `anonymous_asymmetric`, either every key of the group defines `secret_key` or none does. A
mixed state is rejected: a group that can decrypt has to be able to decrypt data encrypted with
its older keys too.

### Naming the type through the enum

`type` is backed by the `HelpPC\EncryptionBundle\EncryptionType` enum. Plain strings keep working,
but both YAML and PHP can name the case instead.

In YAML through Symfony's `!php/enum` tag:

```yaml
encryption:
    groups:
        partner_inbox:
            type: !php/enum HelpPC\EncryptionBundle\EncryptionType::AnonymousAsymmetric
            key_prefix: partner
            active_key: v1
            keys:
                v1:
                    public_key: '%env(PARTNER_PUBLIC_KEY)%'
```

A typo in the case name is then a parse error naming the enum, instead of a value that silently
means nothing.

In PHP configuration the case goes in directly:

```php
// config/packages/encryption.php
use HelpPC\EncryptionBundle\EncryptionType;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\env;

return static function (ContainerConfigurator $container): void {
    $container->extension('encryption', [
        'default_group' => 'default',
        'groups' => [
            'default' => [
                'type' => EncryptionType::Symmetric,
                'key_prefix' => 'adek',
                'active_key' => 'v2',
                'keys' => [
                    'v1' => env('ENCRYPTION_KEY_V1'),
                    'v2' => env('ENCRYPTION_KEY_V2'),
                ],
            ],
            'partner_inbox' => [
                'type' => EncryptionType::AnonymousAsymmetric,
                'key_prefix' => 'partner',
                'active_key' => 'v1',
                'keys' => [
                    'v1' => ['public_key' => env('PARTNER_PUBLIC_KEY')],
                ],
            ],
        ],
    ]);
};
```

Whichever spelling is used, an unknown value is rejected while the configuration is processed:

```
The value "rot13" is not allowed for path "encryption.groups.g.type". Permissible values:
"symmetric", "asymmetric", "anonymous_asymmetric" (cases of the
"HelpPC\EncryptionBundle\EncryptionType" enum).
```

## Usage

The default group is wired to the bare type hints:

```php
use HelpPC\EncryptionBundle\Encryption\Decryptor;
use HelpPC\EncryptionBundle\Encryption\Encryptor;

public function __construct(
    private Encryptor $encryptor,
    private Decryptor $decryptor,
) {
}
```

Other groups are addressed by name:

```php
use Symfony\Component\DependencyInjection\Attribute\Target;

public function __construct(
    #[Target('vault')] private Decryptor $vault,
    #[Target('partner_inbox')] private Encryptor $partnerInbox,
) {
}
```

`#[Target]` accepts both `partner_inbox` and `partnerInbox`. Alternatively use
`#[Autowire(service: 'encryption.partner_inbox')]`.

### Interfaces

| Interface | Methods |
|---|---|
| `Encryptor` | `encrypt`, `isEncrypted`, `needsReEncryption` |
| `Decryptor` | `decrypt` |
| `AdditionalDataEncryptor` (extends `Encryptor`) | `encryptWithAdditionalData` |
| `AdditionalDataDecryptor` (extends `Decryptor`) | `decryptWithAdditionalData` |

The split is deliberate. A write-only group is registered as a class that does not implement
`Decryptor`, and no `Decryptor` alias is created for it, so type-hinting one fails while the
container is being compiled. Anonymous asymmetric groups do not implement the `AdditionalData*`
interfaces, because sealed boxes have no such API in Halite.

### Additional data

Additional data cryptographically binds a cipher text to a context — a row id, a column name, a
tenant id. It is authenticated but **not encrypted**, so it must not be a secret. It prevents a
valid cipher text from being copied from one place to another.

```php
$cipherText = $this->encryptor->encryptWithAdditionalData($addressData, $tenantId);
$plainText  = $this->decryptor->decryptWithAdditionalData($cipherText, $tenantId);
```

The value must be non-empty and **byte identical** on both sides, otherwise decryption fails. Not
available for `anonymous_asymmetric`.

### Key rotation

Add a new key, make it active, and new data is encrypted with it. Old data stays readable as long
as the old key remains configured.

```php
if ($this->encryptor->needsReEncryption($cipherText)) {
    $cipherText = $this->encryptor->encrypt($this->decryptor->decrypt($cipherText));
}
```

Once nothing reports `needsReEncryption()` any more, drop the old key.

`needsReEncryption()` throws on a malformed value. Use `isEncrypted()` — which never throws — when
scanning a column that still holds a mix of plain and encrypted values.

Always generate a fresh key for a new key id. The key id travels in the cipher text
unauthenticated, so two ids must never point at the same key.

### Exceptions

| Exception | When |
|---|---|
| `EncryptionException` | encryption failed; checked |
| `DecryptionException` | malformed cipher text, unknown key id, wrong format, or failed authentication; checked |
| `InvalidEncryptionConfigurationException` | a group cannot be built from its configuration; unchecked, thrown while the container is built |

## Development

```bash
composer phpcs        # coding standards
composer phpstan      # static analysis, level 10
composer rector:check # automated refactors
composer phpunit      # tests
```

## License

MIT
