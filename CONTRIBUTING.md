# Contributing

Development is maintained by su-engineering. Contributions are licensed under Apache-2.0.

## Workflow

1. Create a feature branch and keep each change focused.
2. Preserve did:web and X.509 login behavior unless a migration is part of the change.
3. Add regression tests for behavior changes and update relevant documentation.
4. Run `./mvnw spotless:apply` and `./mvnw clean verify` with Java 21 and Docker available.
5. Open a pull request describing the problem, resulting behavior, validation, and compatibility impact.

Use Conventional Commit messages such as `fix: validate issuer key selection`. The project does not depend on a third-party DCO app or shared organizational workflow.

## Compatibility

Provider IDs, mapper IDs, realm config keys, request paths, persisted flow state, and the installed JAR filename are integration contracts. Test matching Maven and container versions for runtime upgrades. See [migration](docs/migration.md).

Do not commit credentials, real presentations, private keys, generated realms, `.env` files, or internal product documents. Use generated test keys and synthetic claims.

## Tests and releases

See [development](docs/development.md) for test commands. `./mvnw clean verify` is the normal merge check; live OIDF conformance runs require the explicit `conformance` profile and separate configuration.

The repository currently builds development artifacts only. Publishing, version support, and release signing will be configured before the first public release. A push can trigger an existing deployment outside this repository's CI; coordinate deployment branches with the service operator.
