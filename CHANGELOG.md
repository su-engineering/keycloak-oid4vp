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

No public release has been made from this development baseline.
