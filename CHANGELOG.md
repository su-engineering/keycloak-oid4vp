# Changelog

## Unreleased — 0.1.0-SNAPSHOT

Initial independent development baseline under su-engineering.

- Preserve deployed did:web SD-JWT verification, X.509 verification, provider IDs, realm configuration keys, and the OpenKYC login theme.
- Use the `io.github.suengineering.keycloak.oid4vp` Java namespace and `io.github.su-engineering` Maven group.
- Add a pinned Maven wrapper and independent CI without automatic publishing.
- Add combined DID resolution, signature, disclosure, and holder-binding regression tests.
- Pin the wallet E2E fixture and correct stale theme assertions.
- Document configuration, migration, rollback, and work required before enterprise support.
- Rename the repository to `su-engineering/keycloak-oid4vp` while preserving artifact and runtime identifiers.
- Add the opt-in neutral `su-engineering` login theme, with local fonts, responsive wallet login, and inherited Keycloak forms.
- Add a disposable local demo, real theme screenshots, architecture diagrams, and installation/operations guides.
- Add security reporting, contribution guidance, and bundled-theme login regression coverage.
- Rename the OpenKYC login theme to `openkyc`; existing realms must update their theme selection.
- Add a generic realm import and direct wallet browser flow, used by the demo with either theme. Preserve the OpenKYC import as an explicit deployment example.
- Configure deployments through the Admin Console, including newly exposed issuer and proof-timing settings. Allow disabled providers to be configured before their certificates are supplied.
- Preserve authentication-session parameters in the OpenKYC provider-selection links.
- Validate full DCQL JSON when saving provider configuration in the Admin Console, with custom credential examples and guidance on query conditions and response-policy limits.

No public release has been made from this development baseline.
