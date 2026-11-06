# Configuration

The extension is configured as a Keycloak identity provider. All settings are stored in the IdP provider config and can be managed through the Admin UI or realm import JSON.

## Adding the Identity Provider

1. Open the Keycloak Admin Console.
2. Go to **Identity Providers**.
3. Select **OID4VP**.
4. Configure the provider settings.

If you want transient wallet logins, Keycloak must be started with the `transient-users` feature enabled. Then enable the IdP's built-in **Do not store users** option in Keycloak.

Example realm import fragment:

```json
{
  "identityProviders": [
    {
      "alias": "oid4vp",
      "displayName": "Sign in with Wallet",
      "providerId": "oid4vp-wallet",
      "enabled": true,
      "config": {
        "clientIdScheme": "x509_san_dns",
        "responseMode": "direct_post.jwt",
        "x509CertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "walletScheme": "openid4vp://",
        "enforceHaip": "false",
        "dcqlQuery": "{...}"
      }
    }
  ]
}
```

## Configuration checklist

Before choosing defaults, establish the wallet's verifier-authentication requirements, accepted credential issuers and types, claim mapping, user persistence model, and status/revocation policy. A successful demo configuration is not a complete trust policy.

The snippets in this document are fragments. Do not place private signing keys in tracked realm JSON. Configure credential requests, mappers, wallet flows, issuer policy, proof timing, and verifier material under **Identity providers → oid4vp** in the Admin Console. Advanced internal settings such as the cross-device poll interval remain available through realm JSON or the Admin REST API. Use the [generic realm and UI setup guide](installation.md#configure-a-realm) for a new deployment. Select the login theme in **Realm settings → Themes**; direct wallet entry is configured separately under **Authentication → Flows**. See [themes](themes.md).

## Settings

### Credential Request

Use **Identity providers → oid4vp → Settings → DCQL Query (JSON)** to edit the complete request, including custom credential types and claim conditions. See [the DCQL editor guide](dcql.md) for a non-age example, save validation, and the distinction between request conditions and enforced login policy.

| Key | Description | Default |
|-----|-------------|---------|
| `dcqlQuery` | DCQL query JSON defining which credentials to request. If omitted, Keycloak derives the query from configured OID4VP mappers. Manual queries with omitted `meta` receive legacy type inference from their ID; explicit metadata is preserved and, when enabled, `trusted_authorities` is added. | *(auto-generated)* |
| `credentialSetMode` | How credential sets are combined: `optional` or `all`. | `optional` |
| `identityCredentialId` | DCQL query ID providing the login identity and default claims. Must return exactly one presentation when set. | *(first returned query in request order)* |
| `credentialSetPurpose` | Human-readable purpose string included in the DCQL credential set. | *(none)* |
| `requestObjectLifespanSeconds` | Lifespan of the signed request object JWT used by the wallet fetch. | `10` |

### User Mapping

| Key | Description | Default |
|-----|-------------|---------|
| `userMappingClaim` | Claim from an SD-JWT credential used as the unique user identifier. Not required when `useIdTokenSubject` is enabled. Ignored when OID4VP transient users are enabled. | `sub` |
| `userMappingClaimMdoc` | Claim from an mDoc credential used as the unique user identifier. Falls back to `userMappingClaim`. Ignored when OID4VP transient users are enabled. | *(falls back)* |
| `useIdTokenSubject` | When HAIP is disabled, requests an additional self-issued `id_token` and uses its subject as the user identifier. The VP token remains required for credential attributes. Ignored when HAIP is enabled. | `false` |
| `doNotStoreUsers` | Native Keycloak IdP setting. When enabled, OID4VP switches to transient per-login identities, ignores configured identifying claims, and relies on Keycloak transient users. Requires the Keycloak `transient-users` feature to be enabled. | `false` |
| `clockSkewSeconds` | Allowed clock skew for ID token time checks. | `60` |

### Transient Login Mode

To use this extension as a wallet connector without creating persisted Keycloak users:

1. Start Keycloak with the `transient-users` feature enabled.
2. Enable the IdP's built-in **Do not store users** setting.
3. Keep using the normal first broker login flow. Keycloak will create a `LightweightUserAdapter` and a transient user session instead of a stored user.

Behavior in this mode:

- The extension always generates a random per-login transient identifier.
- `userMappingClaim`, `userMappingClaimMdoc`, and `useIdTokenSubject` are ignored for subject resolution.
- OID4VP user-attribute mappers still apply, but the target user is transient and is not persisted after the session ends.
- Session-note mappers are often the best fit when relying parties only need token-time claim propagation.

This mode is intended for credentials that do not carry a stable account identifier, such as German PID variants.

### Flow Control

| Key | Description | Default |
|-----|-------------|---------|
| `sameDeviceEnabled` | Enables same-device wallet login. | `true` |
| `crossDeviceEnabled` | Enables cross-device QR-code wallet login. | `true` |
| `dcApiEnabled` | Offers a wallet in the same browser through the W3C Digital Credentials API. See [Digital Credentials API](#digital-credentials-api). | `false` |
| `dcApiIsoMdocEnabled` | Also offers ISO/IEC 18013-7 Annex C (`org-iso-mdoc`) in that flow when the query is mdoc only. | `true` |
| `walletScheme` | URI scheme used to invoke the wallet app. | `openid4vp://` |
| `responseMode` | Wallet callback response mode: `direct_post` or `direct_post.jwt`. | `direct_post` |

### Client Authentication (X.509)

| Key | Description | Default |
|-----|-------------|---------|
| `clientIdScheme` | Wallet/verifier client ID scheme: `plain`, `x509_san_dns`, or `x509_hash`. | `x509_san_dns` |
| `x509CertificatePem` | PEM-encoded verifier certificate material used for client ID derivation and request-object header material. | *(required for x509 schemes)* |
| `x509SigningKeyJwk` | Explicit signing JWK override. Normally derived automatically. | *(auto-derived)* |
| `verifierInfo` | JSON value for the request object's `verifier_info` claim. | *(none)* |
| `registrationCertificate` | EUDI Wallet relying party registration certificate (`rc-wrp+jwt`). Added to `verifier_info` in every request. See [Relying party certificates](#relying-party-certificates). | *(none)* |

`x509CertificatePem` supports two practical layouts:

1. Combined PEM with leaf certificate, optional intermediate certificates, and private key.
2. Certificate-only PEM when request objects should be signed with the Keycloak realm signing key instead.

#### Relying party certificates

EUDI Wallets expect two certificates from a relying party (ARF Topic 44, ETSI TS 119 411-8 and TS 119 475):

- The **access certificate** (WRPAC) signs the request. It is the leaf of `x509CertificatePem`, sent in the request object's `x5c` header.
- The **registration certificate** (WRPRC) describes what the relying party registered to ask for. Paste the JWT from your registrar into `registrationCertificate`; it is sent with every request (redirect flows and the Digital Credentials API) as `verifier_info` entry `{"format": "registration_cert", "data": "<base64url of the JWT>"}`. If `verifierInfo` already contains a `registration_cert` entry, that entry is used instead.

Wallets refuse requests whose certificates do not fit together, so Keycloak runs the same checks and logs a warning for each problem:

- at startup: the JWT type is `rc-wrp+jwt`, its signature verifies with its `x5c` leaf, it has not expired, its `sub` (or `act.sub` for an intermediary) equals the access certificate's `organizationIdentifier`, and its `serviceIdentifier` equals the access certificate's `organizationalUnit`;
- when a request is built: every credential type and claim the DCQL query asks for is registered in the certificate's `credentials` (a registered parent path such as `address` covers `address.street_address`). Anything else is over-asking (ARF RPRC_21).

Keycloak does not check the registrar's trust chain or revocation status of either certificate; wallets do that against their trusted lists.

### Trust and Verification

| Key | Description | Default |
|-----|-------------|---------|
| `enforceHaip` | Enables the HAIP-oriented effective configuration (`direct_post.jwt` and `x509_hash`). | `true` |
| `trustListUrl` | URL of an ETSI TS 119 602 trust list JWT, or of an ETSI TS 119 612 XML trusted list or the EU list of trusted lists (see [XML trusted lists](#xml-trusted-lists-etsi-ts-119-612)). | *(none)* |
| `trustListServiceTypes` | XML trusted lists only: service type URIs whose granted services anchor issuer chains. | *(none)* |
| `trustListTerritories` | EU list of trusted lists only: country codes of the national lists to load. Empty loads all. | *(none)* |
| `trustListLoTEType` | Expected trust-list LoTE type for this IdP. Keep one trust domain per OID4VP IdP instance. Leave empty only to accept all LoTE types from the configured trust list. | empty |
| `trustedAuthoritiesMode` | DCQL `trusted_authorities` mode: `none`, `etsi_tl`, or `aki`. | `none` |
| `trustListSigningCertPem` | PEM-encoded certificate chain used to verify the trust list JWT signature. Required when `trustListUrl` is set; an unsigned trust list is rejected. | *(none)* |
| `trustListAllowUnsigned` | **Local testing only.** Accept the trust list without verifying its signature when no signing certificate is configured. | `false` |
| `vicalUrl` | Optional VICAL (Verified Issuer Certificate Authority List) whose IACA certificates also anchor mDoc issuer chains. See [mDoc issuer trust](#mdoc-issuer-trust). | *(none)* |
| `vicalSigningCertPem` | PEM certificate(s) the VICAL signature must chain to. Required with `vicalUrl`. | *(none)* |
| `mdocCertificateProfile` | `none` validates mDoc issuer chains only; `iso18013-5` also enforces the ISO/IEC 18013-5 Annex B certificate profiles. | `none` |
| `allowedIssuers` | Comma-separated list of allowed SD-JWT issuer (`iss`) values, or `*`. mDoc credentials are not checked against this list because mDoc does not define a standard canonical credential-issuer string equivalent to SD-JWT `iss`. | `*` |
| `clockSkewSeconds` | Clock skew tolerance for credential verification. | `60` |
| `kbJwtMaxAgeSeconds` | Maximum accepted age of the SD-JWT KB-JWT `iat` claim. | `300` |

For SD-JWT VC verification, issuer-key resolution follows this order:

1. If DID resolution is enabled and the issuer is a DID, resolve it through its explicitly allowed `did:web` or `did:webvh` method. Failure, an unsupported method, or an empty key set rejects the credential; it cannot fall through to certificate or metadata verification. `did:webvh` also rejects when DID resolution is disabled.
2. Validate an `x5c` certificate chain against the configured trust list.
3. Outside strict X.509 mode, try JWT VC issuer metadata via `iss` and JOSE `kid` at `/.well-known/jwt-vc-issuer`, including `jwks_uri`. The resolved key is accepted only if its `x5c` chain is anchored in the trust list. A key published in metadata without an anchored chain is rejected. Issuers without a PKI must use did:web or did:webvh with `allowedIssuers`.
4. Outside strict X.509 mode, try direct trusted certificates as the final fallback.

Trust anchors are used only within their validity period. Only CA certificates anchor a presented chain; a trusted end-entity certificate is accepted only when it is itself the presented leaf. A presented `x5c` chain that fails validation rejects the credential; it is not retried against the trusted keys.

With DID resolution disabled, `enforceHaip=true` restricts this to the `x5c` path. With DID resolution enabled, the earlier DID path is still attempted. Use `enforceHaip=false` for the existing DID flow and read the [DID limitations](#didweb-issuer-verification).

Every returned credential is matched to its own ID in the DCQL query saved for that login. Format, supplied type metadata, claim paths, expected values and required sets are evaluated. Queries can come from the full JSON editor or configured mappers. See [DCQL acceptance rules](dcql.md#request-conditions-and-login-policy).

Use one OID4VP IdP instance per trust domain. If `trustListLoTEType` is configured, it must match the fetched trust list's `ListAndSchemeInformation.LoTEType`. If it is left empty, all LoTE types from that trust list are accepted and the provider logs a warning.
Within the accepted trust list, credential signature verification uses only `.../SvcType/.../Issuance` services.

### XML trusted lists (ETSI TS 119 612)

`trustListUrl` can also point to an ETSI TS 119 612 XML trusted list, or to the EU list of trusted lists (LOTL, `https://ec.europa.eu/tools/lotl/eu-lotl.xml`). Keycloak detects the format from the response.

- The XML signature must be the single enveloped signature directly under the root, cover the whole document (`URI=""`), and verify with a certificate anchored in `trustListSigningCertPem`. Documents with a DOCTYPE are rejected.
- For a LOTL, `trustListSigningCertPem` pins the LOTL itself (the European Commission publishes its signing certificates in the Official Journal). Each national list it points to must be signed by one of the certificates the LOTL lists for it. `trustListTerritories` limits which national lists are loaded; a national list that cannot be fetched or verified is skipped and logged, the others still apply.
- Only services whose current status is granted (or recognised at national level) and whose type is in `trustListServiceTypes` become trust anchors. No type is accepted by default. Do not list broad types such as `http://uri.etsi.org/TrstSvc/Svctype/CA/QC`: every qualified certificate holder chains to those CAs and could then sign credentials. Use the type your credential issuers are registered under, for example `http://uri.etsi.org/TrstSvc/Svctype/EAA/Q` for qualified electronic attestation of attributes.
- The cache follows the earliest `NextUpdate` across the loaded lists, capped by `trustListMaxCacheTtl`. Service history is not evaluated: only the current status counts.
- `trustListLoTEType`, if set, is compared with the list's `TSLType`.

### mDoc issuer trust

mDoc issuer chains (`x5chain` in `issuerAuth`) are anchored in the trust list's issuance services and, when `vicalUrl` is set, in a VICAL such as the AAMVA list of US mobile driving licence issuers.

- The VICAL is a COSE_Sign1 that must verify with an `x5chain` anchored in `vicalSigningCertPem`; an unsigned or unanchored VICAL is never used. It is cached until its `nextUpdate` (at most 24 hours), a failed refresh reuses the cached list for up to `trustListMaxStaleAge`, and a list past its `notAfter` is rejected.
- Each VICAL IACA anchors only documents whose signed docType is listed in its `certificateInfo.docType`.
- If the VICAL cannot be loaded, mDocs are still verified against the trust list alone.

With `mdocCertificateProfile=iso18013-5`, the chain must also meet the ISO/IEC 18013-5 Annex B profiles: the document signer is an end-entity certificate with key usage `digitalSignature` and extended key usage `1.0.18013.5.1.2`, the anchoring IACA is a CA with `keyCertSign`, both carry the same `countryName`, and the MSO `validityInfo.signed` time falls within the document signer's validity. Use it for mobile driving licences. EUDI PID and attestation providers usually follow other profiles, so it is off by default.

### Revocation (Token Status List)

Every Status List Token signature is verified, and an unverifiable token rejects the login. Trust is tried in this order:

1. The trust list's `.../Revocation` services, or its `.../Issuance` services if it lists no revocation services.
2. The keys that verified the referenced credential, which covers DID-based SD-JWT issuers. A list accepted this way is cached only for that issuer.

The status reference must be issuer-signed: for mDoc it is read from the signed MobileSecurityObject, and an SD-JWT `status` claim must not be selectively disclosable. Both Status List Token forms are supported: JWT (`application/statuslist+jwt`) and CWT (`application/statuslist+cwt`, a COSE_Sign1 with an `x5chain` or a key pinned in the trust list). The form is chosen from the response media type, falling back to the body's encoding. Any non-zero status, including suspended (`0x02`), rejects the login. Downloads are capped at 4 MiB and decompressed lists at 16 MiB.

### Caching

Trust lists are cached until the earliest of ETSI `ListAndSchemeInformation.NextUpdate`, HTTP cache headers, and `trustListMaxCacheTtlSeconds` when configured. A trust list whose `NextUpdate` is already in the past is discarded as expired. Trust-list responses without `NextUpdate` are not cached and are not reused as stale fallback. Status lists are cached according to their `ttl` claim when present, capped by `exp` if present; if `ttl` is absent they fall back to `exp`. Status-list responses without both `ttl` and `exp` are treated as immediately expired. JWT VC issuer metadata caching is bounded by HTTP cache headers, `issuerMetadataMaxCacheTtlSeconds`, and each JWK's optional `exp`, whichever expires first.

| Key | Description | Default |
|-----|-------------|---------|
| `statusListMaxCacheTtlSeconds` | Optional maximum cache TTL for token status lists. The effective lifetime uses status-list `ttl` when present, capped by `exp`; otherwise it falls back to `exp`. | *(use status-list ttl / exp)* |
| `trustListMaxCacheTtlSeconds` | Optional maximum cache TTL for trust lists. The effective lifetime is capped earlier by ETSI `NextUpdate` and HTTP cache headers. | *(use trust-list freshness metadata)* |
| `trustListMaxStaleAgeSeconds` | Maximum age of an expired trust-list cache entry that may be reused when refresh fails. Set `0` to disable stale fallback. | `86400` |
| `issuerMetadataMaxCacheTtlSeconds` | Optional maximum cache TTL for JWT VC issuer metadata and resolved issuer JWKS. The effective lifetime is capped earlier by HTTP `Cache-Control` and any JWK `exp`. Set `0` to disable issuer-metadata caching. | `86400` |

### Digital Credentials API

With `dcApiEnabled=true` the login page loads `oid4vp-dc-api.js`, which shows "Use a wallet in this browser" only when the browser exposes `DigitalCredential` and `navigator.credentials.get()`. Other browsers see the page unchanged.

| Setting | Request sent to the browser |
|---------|-----------------------------|
| Client ID scheme `x509_san_dns` or `x509_hash` with `x509CertificatePem` set | Signed request object (`openid4vp-v1-signed`) with `client_id` and `expected_origins` |
| `plain`, or no verifier certificate | Unsigned request (`openid4vp-v1-unsigned`) |
| `responseMode=direct_post.jwt`, or `enforceHaip=true` | `response_mode=dc_api.jwt` with an ephemeral P-256 key in `client_metadata` |
| `responseMode=direct_post` | `response_mode=dc_api` |

`expected_origins` and the presentation binding use the origin of Keycloak's front-end URL, so the login page must be served from that origin (set `hostname` when Keycloak runs behind a proxy). The wallet binds every presentation to that origin: the SD-JWT key binding JWT `aud` must be `origin:<origin>`, and mDoc device authentication must use the `OpenID4VPDCAPIHandover` transcript. A presentation made for a redirect flow, or for another site, is rejected.

#### ISO mdoc (Safari and Apple Wallet)

Safari and Apple Wallet answer only ISO/IEC 18013-7 Annex C (`org-iso-mdoc`). When `dcApiIsoMdocEnabled` is on and every DCQL credential query is `mso_mdoc` with its own `doctype_value` and `[namespace, element]` claim paths, the page offers an ISO request next to the OpenID4VP one and the browser or wallet picks one.

- The response is always encrypted with HPKE to a key made for that request, and the encryption is bound to the Keycloak origin. The mdoc is then verified like any other: issuer chain against the trust list, digests, validity, revocation, and device authentication over the Annex C session transcript.
- With `x509SigningKeyJwk` and `x509CertificatePem` set to a P-256 key, the DeviceRequest is version 1.1 and signed with `readerAuthAll` (ES256, certificate chain in `x5chain`). Apple Wallet only answers signed requests, and the certificate has to come from Apple Business Connect. Without such a key the request is an unsigned version 1.0 DeviceRequest.
- DCQL `credential_sets` become DeviceRequest use cases. Claim `values` are not sent to the wallet, but they are still checked on the response.

The flow is not offered while `useIdTokenSubject` is on, because the browser API returns no SIOP ID token. Trust lists, status lists, issuer allowlists and mappers apply as in the redirect flows.

### Cross-Device Status Polling

| Key | Description | Default |
|-----|-------------|---------|
| `crossDevicePollIntervalMs` | How often the cross-device login page asks Keycloak whether the wallet has finished. Clamped to 500–30000 ms. The pre-0.1.0 key `ssePollIntervalMs` is read when this key is unset. | `2000` |
| `crossDeviceCompleteTtlSeconds` | Lifetime of the cross-device completion marker. The deferred auth record itself uses the realm login timeout. | `300` |

## IdP Mappers

The extension provides two mapper types:

- `OID4VP Claim to User Attribute`
- `OID4VP Claim to User Session Note`

Each mapper can select a DCQL query ID, credential format, credential type, and claim path. Claims from different credentials are retained separately; see [multi-credential mapping](multiple-credential-types.md#identity-and-claim-mapping). When `dcqlQuery` is not set manually, these mappers drive the generated DCQL request.

## Multi-Node Behavior

Cross-device completion depends on a shared Keycloak `SingleUseObjectProvider`. The login page polls `/cross-device/status` with short, ordinary requests; any node can answer because each poll reads the shared completion marker and holds no connection or thread open between polls. No cluster notification channel or sticky session is required, but the single-use object store and authentication sessions must be shared.

## did:web issuer verification

DID issuer verification is opt-in and is independent of the verifier certificate used to sign wallet requests. These settings apply to both methods; see [did:webvh setup and validation](did-webvh.md) for the history-verifying resolver.

| Key | Behavior in this compatibility baseline | Default |
| --- | --- | --- |
| `didResolutionEnabled` | Resolve enabled DID methods for SD-JWT issuers. Resolution failure rejects the credential. | `false` |
| `didCacheTtlSeconds` | Lifetime of entries in each resolver instance's in-memory cache. | `3600` |
| `allowedDidMethods` | Enforced comma-separated method list: `did:web`, `did:webvh`, or both. | `did:web` |
| `allowedIssuers` | Existing SD-JWT issuer policy. Use explicit issuer DIDs for restricted deployments. | Existing wildcard policy |
| `didWebLegacyPathLayout` | Compatibility only: resolve path DIDs from `<path>/.well-known/did.json` as releases up to `0.1.0-rc.1` did. | `false` |

The resolver follows the did:web layout: a host DID resolves to `https://issuer.example/.well-known/did.json`, a path DID such as `did:web:issuer.example:tenant` to `https://issuer.example/tenant/did.json`, and an encoded port (`did:web:issuer.example%3A8443`) to `https://issuer.example:8443/.well-known/did.json`. Releases up to `0.1.0-rc.1` fetched path DIDs from `<path>/.well-known/did.json`; set `didWebLegacyPathLayout=true` while such issuers migrate. Documents are capped at 256 KiB.

Key authorization: the document `id` must equal the DID, only keys referenced in `assertionMethod` (by relative or absolute ID, or embedded) are eligible, a method whose `controller` is another DID is skipped, and a JOSE `kid` must name one of the eligible keys. Without a `kid`, all eligible keys are tried.

The resolver supports JWK public keys including EC and Ed25519. Its multibase implementation accepts only the specific Ed25519 forms implemented in `DidWebResolver`; do not assume all multibase/multicodec documents are supported.

DID resolution precedes strict X.509 handling, so enabling it is not a claim of HAIP conformance. Use `enforceHaip=false` for the existing DID flow and review the [readiness plan](enterprise-readiness.md) before changing trust policy.
