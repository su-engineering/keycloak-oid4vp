# Security policy

## Report a vulnerability

Email **[security@su.engineering](mailto:security@su.engineering)** privately. Do not open a public issue or pull request containing exploit details or live credentials.

Include:

- The extension revision and Keycloak version.
- The affected configuration and trust path (did:web, X.509, or issuer metadata).
- Reproduction steps using synthetic credentials, expected behavior, and observed impact.
- A minimal proof of concept and relevant redacted logs, if available.

Never send production private keys, access tokens, full real presentations, or personal credential data. If your report needs sensitive attachments, contact us first to agree on a transfer method.

We will review the report, coordinate any fix and disclosure with the reporter, and credit the reporter with permission. There is no published response-time SLA or bug-bounty program.

## Supported versions

The project currently has a development baseline (`0.1.0-SNAPSHOT`) and no public release support schedule. Security fixes will be developed on `main`; a versioned support policy will accompany public releases. The Keycloak CI matrix describes tested compatibility, not a security support commitment from this project or Keycloak.

## Known limitations

Read the [enterprise readiness plan](docs/enterprise-readiness.md) and [DID verification notes](docs/configuration.md#didweb-issuer-verification) when evaluating an integration. This baseline does not claim an independent security audit, OIDF certification, or HAIP conformance.

Development wallets, generated certificates, example credentials, and relaxed test settings are for isolated development. Configure production trust, secrets, network access, logging, and backups deliberately.
