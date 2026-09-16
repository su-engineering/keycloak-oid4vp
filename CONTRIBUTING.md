# Contributing

We welcome reproducible bug reports, focused fixes, tests, and clear documentation. Read the [code of conduct](CODE_OF_CONDUCT.md) and use [private reporting](SECURITY.md) for vulnerabilities.

## Before changing code

Start with the [local demo](docs/quickstart.md), [development guide](docs/development.md), and [architecture](docs/diagrams.md). For a large protocol, trust-policy, or runtime change, open an issue describing the problem and compatibility impact before implementing it.

Bug reports should identify the extension revision, Keycloak version, relevant wallet/credential format, expected result, and minimal reproduction. Use synthetic credentials and redacted configuration.

## Contribution workflow

1. Create a feature branch and keep the change focused.
2. Preserve did:web and X.509 login behavior unless the change includes an explicit migration.
3. Add meaningful regression coverage for changed behavior and update the affected guides.
4. Run `./mvnw spotless:apply` and `./mvnw clean verify` using Java 21 and Docker.
5. For runtime or SPI changes, also run the other pinned Keycloak version; see [development](docs/development.md).
6. Open a pull request explaining the problem, resulting behavior, validation, and compatibility impact. Include screenshots for theme changes and migration/rollback details when needed.

Use Conventional Commit messages, for example `fix: validate issuer key selection` or `docs: explain DID trust configuration`.

## Compatibility contracts

Provider IDs, mapper IDs, realm config keys, endpoint paths, stored flow state, and the installed JAR filename are integration contracts. Test matching Maven and container versions when upgrading the runtime. Keep issuer trust separate from verifier authentication. See [migration](docs/migration.md).

Theme changes must preserve the wallet form fields, links, QR payload, and SSE configuration. Keep OpenKYC compatibility unless a dedicated change is agreed. The neutral theme's copy must remain independent of a particular credential issuer or wallet vendor.

## Documentation and assets

- Keep the README focused on purpose, status, first use, and navigation.
- Put configuration details in the reference guide and link to them from tutorials.
- Label incomplete JSON as a fragment and verify commands from a clean checkout.
- Use Mermaid for architecture and sequence diagrams.
- Capture screenshots from the local demo with synthetic data; see [themes](docs/themes.md).
- Check relative links, image paths, and headings when moving content.

Do not commit real presentations, private keys, access tokens, generated realms, `.env` files, or internal product documents. Preserve license notices and include provenance for vendored assets.

## License and releases

Contributions are provided under the repository's Apache-2.0 license. Third-party assets retain their own licenses. This project does not require a shared organizational workflow or third-party DCO application.

Versioned tags publish tested JARs and checksums through the [release workflow](docs/releases.md). Prereleases are intended for integration testing; stable releases require deployment-specific issuer/wallet acceptance testing. A push can trigger deployment configured outside repository CI; coordinate deployment branches with the service operator.
