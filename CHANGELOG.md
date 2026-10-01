# Changelog

## Unreleased

- Self-host the OpenKYC theme fonts (Inter, Plus Jakarta Sans, JetBrains Mono) so login pages make no requests to Google Fonts.

## 0.1.0-rc.1 — 2026-09-16

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

- Add opt-in did:webvh v1.0 SD-JWT issuer resolution with signed history, pre-rotation and witness validation, current assertion-key selection, bounded HTTPS reads and caching.
- Enforce the configured DID method list and reject DID resolution failures without certificate/metadata fallback.
- Document multiple credential types using DCQL alternatives, multiple providers, or separate realms with independent SSO.

No public release has been made from this development baseline.

- Verify multiple credential types and formats in one DCQL response, including repeated presentations, query-specific claims/values, and required/alternative sets from the saved request.
- Add identity query selection and query-scoped claim mappers in the Admin Console. Preserve all credential claims through deferred login; check every SD-JWT issuer and reject ambiguous scalar mappings.
- Require mDoc device proofs during login and reject extra embedded documents instead of silently taking the first. Document multi-credential setup and migration behavior.

- Publish versioned GitHub releases with tested JARs for Keycloak 26.5.4 and 26.5.5, SHA-256 checksums, and release notes.
- Make the synthetic realm import readable by the non-root Keycloak container user so CI can run wallet/browser integration tests.
