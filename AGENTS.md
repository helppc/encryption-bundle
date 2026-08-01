# AGENTS Instructions

## Required Checks
Run all of the following before committing:

```bash
composer phpcs       # coding standards
composer phpstan     # static analysis
composer rector:check # rector rules
composer phpunit     # tests
```

## Helpful Tools
- `composer phpcbf` – automatically fix coding standard issues
- `composer rector:apply` – apply Rector automated refactors


## Coding rules

- Never write cryptographic primitives in this repository. All cryptography goes through
  `spaze/encryption`; this bundle only wraps it in a typed facade and Symfony configuration.
- Every new PHP file must start with `declare(strict_types=1);`.
- Follow PSR-12 and use typed parameters and return types.
- Code must run on the PHP version specified in `composer.json` (currently `>=8.4`).
- Before submitting changes run `composer phpstan`, `composer phpunit`, `composer phpcs` and `composer rector:check`.
- Changes must pass PHPStan at level 10 together with all rules from `phpstan.neon`.
- New features should have corresponding tests in the `tests/` directory.
- Write commit messages in English and briefly describe what was changed.
- Do not use property hooks.
- Use `DateTimeImmutable` whenever creating dates and prefer `Symfony\Component\Clock\Clock::get()->now()` for consistent timestamps across the application.

## Dependency note

`spaze/encryption` is required as `dev-main` because asymmetric encryption is merged upstream
but not tagged yet — the latest tag, `v2.3.2`, only ships `SymmetricKeyEncryption`. Once a tag
containing the asymmetric classes is released, narrow the constraint to that version and set
`minimum-stability` back to `stable`.

Only classes that exist in **upstream** `spaze/encryption` may be referenced. The
`helppc/encryption` fork carries extra contracts and a marker exception interface that upstream
does not have; this bundle must not depend on them.
