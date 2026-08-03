# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- README section on upgrading to `spaze/encryption` 3.0: version 3 writes a marked cipher text
  format that older deployments cannot read, so every reader has to be upgraded before the first
  new write.

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
