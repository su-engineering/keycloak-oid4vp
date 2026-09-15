# Enterprise readiness: discussion draft

The deployed did:web SD-JWT flow is the compatibility baseline. These findings come from code inspection and comparison with later verifier changes; they are not a completed security audit. Address them in separate, tested changes before advertising enterprise support.

## Credential trust and login integrity

| Area | Current evidence | Proposed acceptance criteria |
| --- | --- | --- |
| DID key authorization | `DidWebResolver.filterByKeyId` returns every verifier; the resolver does not validate document `id`, controller, or `assertionMethod`. | Reject unrelated documents, unknown `kid`, and unauthorized assertion keys; test rotation and existing issuer documents. |
| DID URLs | Path DIDs use `/<path>/.well-known/did.json`; the identifier is decoded before splitting on colons. | Agree a migration to standard path/port handling with deliberate compatibility for deployed issuers. |
| Network access | DID fetches use credential-supplied locations without an explicit destination allow-list, document-size bound, or bounded shared cache in the resolver. | Define HTTPS/egress policy, redirects, timeouts, size bounds, and bounded caching. |
| Configuration | `allowedDidMethods` is exposed but not used to select the resolver. DID resolution runs before strict X.509 handling. | Specify and test method enforcement, fallback policy, and high-assurance profile interaction. |
| Issuer policy | The callback checks the primary credential issuer; multi-credential trust needs review. | Enforce issuer policy for every credential used to authenticate or populate claims. |
| Login completion | Completion uses public request handles plus the authentication session; later designs add a single-use response code and reject repeated successful submissions. | Reproduce relevant attacks, then test replay rejection, abandoned-attempt isolation, and cross-device completion across nodes. |
| Revocation | The static status-list cache uses only the URI; decompression is unbounded; without trust certificates, signature verification is skipped. | Isolate cache entries by trust policy, bound decompression, and define signed-status trust for DID issuers. |

## Reliable operation

- **Version policy:** select supported Keycloak/Java versions and test exact images. Upgrade runtime libraries separately from this cleanup.
- **Health checks:** the Coolify probe uses `curl` and `|| exit 0`, so it can report success without a healthy server. Replace it after validating the container's management endpoint.
- **Secrets and initialization:** separate examples from production realms, remove permissive credentials/redirects from production defaults, and move verifier private keys out of image layers. Generated and static imports currently target the same realm filename and need a deliberate initialization policy.
- **Clustering:** test replay races, node loss, cache invalidation, SSE reconnects, and rolling changes against the shared state store.
- **Existing OpenKYC login selection:** its generic login template constructs a broker link without the authentication-session query parameters. Preserve direct entry through `kc_idp_hint=oid4vp` and review a separate fix; the neutral theme uses inherited Keycloak provider links.
- **Observability:** structured errors, latency and resolution metrics, readiness, and logs without credential claims, presentations, or private material.
- **Resource limits:** test malformed and oversized presentations, DCQL complexity, request concurrency, and slow issuer endpoints.

## Before a public release

- Test a complete did:web wallet-to-Keycloak flow against the release image, in addition to cryptographic tests and the certificate-based E2E suite.
- Publish supported features and limitations. A passing happy path is not a conformance claim.
- Run the OIDF suite where applicable and document the profiles it validates.
- Maintain the private vulnerability route in [SECURITY.md](../SECURITY.md); define versioned support, signed releases, artifact inventory/SBOM, and dependency review cadence before public releases.
- Review tracked examples and the initial commit for private material. Keep required licenses and attribution in source and artifacts.

Suggested order: trust and login integrity, deployment reliability, runtime upgrades, then public release automation. This cleanup preserves behavior so these decisions can be reviewed independently.
