# Changelog

## Unreleased

- Accept ETSI TS 119 612 XML trusted lists and the EU list of trusted lists (LOTL) as the trust list. The XAdES enveloped signature must cover the whole document and verify with a certificate anchored in `trustListSigningCertPem`; a LOTL is followed to the national lists, each verified with the certificates the LOTL names for it, optionally limited by `trustListTerritories`. Only granted services of the types in the new `trustListServiceTypes` setting become trust anchors; no type is accepted by default.
- Add `registrationCertificate` for the EUDI Wallet relying party registration certificate (ETSI TS 119 475, `rc-wrp+jwt`). It is sent in `verifier_info` with every request as a `registration_cert` entry. At startup Keycloak logs a warning when its type, signature or expiry is wrong or when it is not bound to the access certificate (`organizationIdentifier` and `organizationalUnit`), and it warns when the DCQL query asks for credentials or claims the certificate does not register (ARF RPRC_21).
- Add VICAL support for mDoc issuer trust. `vicalUrl` and `vicalSigningCertPem` load a signed VICAL (for example the AAMVA list of US mobile driving licence issuers); its IACA certificates anchor mDoc issuer chains for the docTypes each entry lists, next to the trust list. A failed refresh reuses the cached list within `trustListMaxStaleAge`, and an unavailable VICAL never blocks mDocs the trust list anchors.
- Add `mdocCertificateProfile=iso18013-5` to enforce the ISO/IEC 18013-5 Annex B certificate profiles on mDoc issuer chains: document signer key usage and `id-mdl-kp-mdlDS` extended key usage, an IACA with `keyCertSign`, matching `countryName`, and an MSO signed within the document signer validity. The default `none` keeps chain validation only.
- Offer ISO/IEC 18013-7 Annex C (`org-iso-mdoc`), the mdoc protocol of Safari and Apple Wallet, next to OpenID4VP in the Digital Credentials API flow. It is used when every DCQL credential query is an mdoc with its own docType, and can be turned off with `dcApiIsoMdocEnabled=false`. Responses are HPKE-encrypted (DHKEM(P-256), HKDF-SHA256, AES-128-GCM) and bound to the Keycloak origin through the `dcapi` session transcript. With a P-256 X.509 signing key the DeviceRequest is version 1.1 and signed with `readerAuthAll`; Apple Wallet only answers requests signed with a certificate issued through Apple Business Connect.
- The `/dc-api/request` endpoint now answers `{state, requests: [{protocol, data}, ...]}`, and the page posts the answering `protocol` back with the response.
- Sign in with a wallet in the same browser through the W3C Digital Credentials API (OID4VP 1.0 Appendix A). Enable `dcApiEnabled`; the login page then shows "Use a wallet in this browser" in browsers that support the API. Requests are signed (`openid4vp-v1-signed`, with `expected_origins`) when the client ID scheme is certificate-bound and a verifier certificate is configured, and unsigned (`openid4vp-v1-unsigned`) otherwise. Responses use `dc_api.jwt` when the response mode is `direct_post.jwt` or HAIP is enforced, and `dc_api` otherwise. Presentations are bound to the Keycloak origin: the SD-JWT key binding audience must be `origin:<origin>` and mDoc device authentication uses the `OpenID4VPDCAPIHandover` session transcript.
- Accept an `x5c` or `x5chain` that includes its trusted issuing CA. Issuers commonly send the CA named in the trust list along with their certificate; such chains were rejected as not anchored unless the CA was self-signed.
- Support Token Status Lists in CWT form (`application/statuslist+cwt`) alongside JWT. CWT lists are COSE_Sign1 tokens verified through an anchored `x5chain`, a pinned trust-list key, or the referenced credential's issuer keys. Lists are fetched as raw bytes with a 4 MiB limit.
- **Breaking:** did:web key authorization. The DID document `id` must equal the DID, only `assertionMethod` keys controlled by the DID may sign credentials, and a JOSE `kid` must name one of them.
- **Breaking:** did:web URLs follow the did:web specification. Path DIDs resolve to `<path>/did.json` and encoded ports (`%3A`) stay in the host. Set `didWebLegacyPathLayout=true` to keep the previous `<path>/.well-known/did.json` layout. DID documents are capped at 256 KiB.
- **Breaking:** a configured trust list must be signed. Without `trustListSigningCertPem` the trust list is now rejected instead of being trusted as fetched. The new `trustListAllowUnsigned` option restores the old behaviour for local testing only.
- Correct the Admin Console help text: the trust list is an ETSI TS 119 602 List of Trusted Entities in its JSON/JWT binding, not a TS 119 612 XML trusted list, and an empty Trust List URL does not skip signature verification.
- Token Status List signatures are always verified. Trust comes from the trust list's revocation services, otherwise its issuance services, otherwise the keys that verified the referenced credential (for example a did:web issuer). A token that none of these can verify is rejected. Cached lists verified with one issuer's own key are not reused for other issuers.
- mDoc revocation is checked against the `status` in the signed MobileSecurityObject instead of the disclosed data elements. An SD-JWT `status` claim must be issuer-signed; a selectively disclosable one is rejected.
- Bound status list downloads to 4 MiB and decompressed lists to 16 MiB.
- Issuer keys resolved from `/.well-known/jwt-vc-issuer` metadata now require a certificate chain anchored in the trust list. Issuers without a PKI should use did:web or did:webvh with an explicit issuer allowlist.
- mDoc issuer authentication now requires the document signer certificate in `x5chain` and a chain that validates against the trust anchors; it no longer falls back to trying every trusted key directly. The MSO is mandatory, its `digestAlgorithm` (SHA-256/384/512) is honoured, every disclosed namespace and item must have a digest, and `validityInfo` with `validFrom` and `validUntil` is required.
- X.509 trust anchors must be within their validity period, and only CA certificates may anchor a presented chain; a trusted end-entity certificate is accepted only as the presented leaf itself. A JWT whose `x5c` chain fails validation is rejected instead of being retried against the trusted keys.
- **Breaking:** rename the identity provider ID from `oid4vp` to `oid4vp-wallet` so the extension can be installed next to Keycloak's native experimental OID4VP provider, which uses `oid4vp`. Existing deployments must run `scripts/migrate-provider-id.sql`; realm aliases, broker URLs, mappers and linked identities are unchanged. See the migration guide.
- **Breaking:** require Keycloak 26.8.x. CI and release JARs now target 26.8.0 and 26.8.1; 26.5.x is no longer built or tested. Keycloak 26.8 marks the transaction rollback-only when an error page is rendered; the provider's error paths do not depend on writes made earlier in the same request.
- Fix intermittent login and admin failures caused by the cross-device server-sent event stream, which kept a Keycloak session and transaction open across a suspended request and could corrupt state for unrelated requests. The cross-device login page now polls `/cross-device/status`, which returns `{"status":"pending"}`, `{"status":"complete","redirect_uri":...}`, or `204` when the flow is unknown, expired, or belongs to another browser.
- Replace `ssePollIntervalMs` with `crossDevicePollIntervalMs` (default 2000 ms, clamped to 500–30000 ms); the old key is still read when the new one is unset. `sseTimeoutSeconds` and `ssePingIntervalSeconds` are removed and ignored.
- Rename the theme script to `oid4vp-cross-device-status.js` and its configuration element to `oid4vp-cross-device-status-config`; custom themes that copied the old SSE script must switch to the new one.
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
