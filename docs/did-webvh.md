# did:webvh issuer verification

The extension can verify SD-JWT credentials whose `iss` is a `did:webvh` DID. It fetches and validates the complete `did.jsonl` history before using the current document's credential-signing keys. This is separate from the verifier keys used to sign the wallet's authorization request.

## Configure in Keycloak

In your realm, open **Identity providers → your OID4VP provider → Settings**:

1. Turn on **Enable DID Resolution**.
2. Set **Allowed DID Methods** to `did:webvh`, or `did:web,did:webvh` to accept both. The default remains `did:web`.
3. Set **Allowed Issuers (SD-JWT)** to the full issuer DID(s) you trust, separated by commas. A resolvable, correctly signed DID is not automatically a trusted credential issuer.
4. Set **DCQL Query (JSON)** to your credential type and claims. Configure claim mappers separately; see [DCQL editing](dcql.md).
5. Use the existing DID integration with **Enforce HAIP** disabled. DID support does not establish HAIP conformance. Configure the verifier's request-signing keys and wallet settings as described in [installation](installation.md).

No external universal resolver service is required. The provider JAR bundles the pinned `didwebvh-core` 0.3.1 history-validation dependency. HTTPS uses Keycloak's shared HTTP client and trust configuration. The upstream Base58 facade is replaced with a small Apache-2.0 adapter in this repository; its GPL-backed implementation and dependency are excluded from the JAR.

## Issuer requirements

For `did:webvh:<SCID>:issuer.example`, publish the log at `https://issuer.example/.well-known/did.jsonl`. For `did:webvh:<SCID>:issuer.example:credentials`, publish at `https://issuer.example/credentials/did.jsonl`. `<SCID>` is the identifier derived from the initial log entry, not an arbitrary string. An encoded domain port such as `issuer.example%3A8443` is supported.

The current DID document must authorize the credential-signing key in `assertionMethod`, either by reference to `verificationMethod` or as an embedded method. Each selected key must be controlled by that DID. Use the full verification-method ID or its `#fragment` as the credential JWT's `kid`; an unknown key ID is rejected. If `kid` is absent, the verifier tries the document's authorized assertion keys.

Supported credential-signing material is a public JWK understood by Keycloak's signature providers (EC, RSA, or OKP), or an Ed25519 `publicKeyMultibase`. P-256 JWK and Ed25519 multikey SD-JWT presentations have cryptographic regression coverage. Encryption-only and private keys are rejected. Other multikey codecs are not implemented. Runtime checks use Keycloak's default crypto provider; FIPS mode is not validated.

The log-update key and credential-signing key can be different. Log and witness proofs use `eddsa-jcs-2022` with Ed25519 keys, as required by WebVH v1.0. Witness identifiers use `did:key`; this does **not** enable `did:key` as a credential issuer method.

## Validation and limits

- Validates the SCID, chained entry hashes, sequential versions, timestamps, update-key authorization, and pre-rotation commitments. Checks proof type, suite, purpose, and matching proof-key DID/fragment.
- Fetches `did-witness.json` beside the log whenever witnessing is active anywhere in the history, and verifies the required witness thresholds, including changes to the witness list. Missing or invalid required witnesses reject resolution.
- Rejects deactivated DIDs. Uses only the latest document: old credential-signing keys must remain authorized there if old credentials should still verify. Historical `versionId`/`versionTime` queries in credential issuers are not supported.
- Validates portable moves while preserving the SCID and prior-DID linkage. Credentials must use the current DID. Moving an issuer also requires updating its entry in **Allowed Issuers**; an `alsoKnownAs` entry does not extend the issuer allowlist.
- Supports `parameters.method = did:webvh:1.0`. Other versions, duplicate JSON keys, and fields/types that the pinned validation models cannot preserve are rejected. Bare multikey witness identifiers are rejected; publish `did:key` identifiers.
- Limits each HTTP artifact to 1 MiB and a history to 512 entries. Connect, socket-read, and connection-pool waits are limited to 10 seconds each. HTTP redirects are rejected.
- Caches validated documents per resolver instance, for the smaller of **DID Cache TTL** and the log's `ttl`, with at most 128 documents per instance. A zero TTL disables caching. Expired entries are not reused after a fetch failure.

When DID resolution is enabled, an unsupported/disabled method, missing key, or resolution failure rejects the credential. It does not fall back to X.509 or issuer metadata. A `did:webvh` issuer also fails when DID resolution is off, so attaching a certificate cannot bypass history verification. HTTPS issuer credentials continue using the existing certificate/metadata paths.

History validation detects tampered chains; it does not by itself prove that a host supplied the newest available chain. This integration does not persist checkpoints across resolver instances or query independent watchers. Credential acceptance also follows the saved [DCQL login policy](dcql.md#request-conditions-and-login-policy).

References: [WebVH v1.0 specification](https://identity.foundation/didwebvh/v1.0/), [pinned Java implementation](https://github.com/decentralized-identity/didwebvh-java/tree/v0.3.1).
