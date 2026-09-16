# Documentation

Start with [the local demo](quickstart.md), then [install the provider](installation.md) in your own test realm. The extension is a development baseline; [known limitations](enterprise-readiness.md) are part of the integration contract.

## Learn

- [Quick start](quickstart.md) — run Keycloak and a development wallet without private credentials.
- [Architecture and diagrams](diagrams.md) — application, wallet, verifier, and trust sources.
- [Request flow](request-flow.md) — implementation walkthrough and stored-state lifecycle.
- [Themes](themes.md) — neutral su.engineering appearance, screenshots, and customization.

## Integrate and operate

- [Releases](releases.md) — download verified provider JARs or publish a versioned release.
- [Installation](installation.md) — artifact, runtime versions, container build, and first setup.
- [Configuration](configuration.md) — provider settings, DID behavior, DCQL, and mappers.
- [DCQL JSON editor](dcql.md) — custom credentials, claim conditions, examples, and validation in the Admin Console.
- [did:webvh issuer verification](did-webvh.md) — history validation, witnesses, supported keys, and Admin Console setup.
- [Multiple credential types](multiple-credential-types.md) — require credentials together, accept alternatives, configure mappers, or isolate policies in realms.
- [Operations](operations.md) — troubleshooting, logging, proxy behavior, and release validation.
- [Migration and rollback](migration.md) — stable contracts and upgrade boundaries.
- [Coolify deployment](../deployment/README.md) — the existing deployment configuration.

## Contribute and evaluate

- [Development](development.md) — toolchain, tests, coverage, and sandbox workflows.
- [Conformance](conformance.md) — optional OIDF testing; no certification is claimed.
- [Load testing](../loadtest/README.md) — clustered browser and SSE scenarios.
- [Enterprise readiness](enterprise-readiness.md) — outstanding trust and operational work.
- [Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md) · [Changelog](../CHANGELOG.md).

Examples use synthetic data. Configuration snippets are labeled as fragments when they cannot be imported directly. Commands run from the repository root unless stated otherwise.
