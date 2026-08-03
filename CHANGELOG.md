# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- README section on upgrading to `spaze/encryption` 3.0: version 3 writes a marked cipher text
  format that older deployments cannot read, so every reader has to be upgraded before the first
  new write.
- PHP 8.5 to the CI matrix, so the suite runs on every version `composer.json` allows, not only on
  the lowest one.
- A deprecation policy that actually holds: a deprecation this bundle triggers itself fails the
  test run, one reached through a Symfony internal does not.

### Changed

- **BREAKING**: an `anonymous_asymmetric` key with an explicitly empty `secret_key` is now rejected
  while the container is compiled. It used to be treated as no secret key at all, which silently
  turned the group write-only. Leave `secret_key` out to get a write-only group.
- `symfony/framework-bundle` moved to `require-dev`. No production class of this bundle references
  it, so installing the bundle no longer pulls in the whole framework.

### Fixed

Documentation that promised more than the implementation delivers. No behaviour changed by these,
but code written against the old wording may have been resting on a guarantee that was not there:

- `InvalidEncryptionConfigurationException` was described as thrown while the container is built.
  Only the shape of the configuration fails there; key material — prefix, encoding, length, role,
  key pair — is validated when the encryption service is created, because resolving `%env()%` at
  compile time would write the keys into `var/cache/`.
- `needsReEncryption()` promised a `DecryptionException` for anything that is not cipher text of
  this group. It is a structural check: it verifies neither that the key id is configured nor that
  the payload authenticates, so a structurally valid value with an unknown key id reports `true`.
- The key id was described as travelling unauthenticated in every value. Since upstream 3.0 that
  holds only for `anonymous_asymmetric` and for values written without a marker; the new
  `symmetric` and `asymmetric` format binds the key id and the marker into what decryption verifies.
- The keygen prefix section read as if a prefix containing `_` were invalid configuration. It is a
  rule of the command; a matching `key_prefix` with an underscore works at runtime.

## [1.0.0] - 2026-08-03

### Added

- Symfony bundle exposing a typed encryption facade over `spaze/encryption`: one service per
  configured group, interfaces narrow enough that a write-only group never gets a `Decryptor`.
- Three encryption types — `symmetric`, `asymmetric` and `anonymous_asymmetric` — configured
  through the `EncryptionType` enum, a YAML string, or Symfony's `!php/enum` tag.
- Additional authenticated data for `symmetric` and `asymmetric` groups.
- `encryption:generate-key` command producing prefixed keys and key pairs.

### Changed

- Requires the stable upstream `spaze/encryption` `^3.0` instead of a fork.

[Unreleased]: https://github.com/helppc/encryption-bundle/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/helppc/encryption-bundle/releases/tag/v1.0.0
