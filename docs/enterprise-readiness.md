# Enterprise readiness: discussion draft

The deployed did:web SD-JWT flow is the compatibility baseline. These findings come from code inspection and comparison with later verifier changes; they are not a completed security audit. Address them in separate, tested changes before advertising enterprise support.

## Credential trust and login integrity

| Area | Current evidence | Proposed acceptance criteria |
| --- | --- | --- |
| did:web key authorization | `DidWebResolver.filterByKeyId` returns every verifier; the resolver does not validate document `id`, controller, or `assertionMethod`. | Reject unrelated documents, unknown `kid`, and unauthorized assertion keys; test rotation and existing issuer documents. |
| did:web URLs | Path DIDs use `/<path>/.well-known/did.json`; the identifier is decoded before splitting on colons. | Agree a migration to standard path/port handling with deliberate compatibility for deployed issuers. |
| Network access | Legacy did:web fetches lack size/cache bounds. did:webvh has bounded reads/cache and rejects redirects; both use credential-supplied DNS locations without an explicit destination allow-list. | Define HTTPS/egress policy, redirects, timeouts, size bounds, and bounded caching. |
| Configuration | `allowedDidMethods` now selects the resolver; enabled DID resolution fails closed. DID resolution runs before strict X.509 handling. | Validate the deployed issuer migration and high-assurance profile interaction. |
| Issuer policy | Issuer allow-lists apply to every SD-JWT credential; each mDoc uses certificate trust. | Continue independent trust-policy review and conformance testing. |
| DCQL conditions | Responses are checked against saved query IDs, formats, types, paths, values and required sets. Mixed formats and repeated presentations are retained separately. | Add wallet interoperability and conformance coverage; cross-credential subject relationships and arbitrary condition languages remain outside this policy. |
| Login completion | Completion uses public request handles plus the authentication session; later designs add a single-use response code and reject repeated successful submissions. | Reproduce relevant attacks, then test replay rejection, abandoned-attempt isolation, and cross-device completion across nodes. |
| Revocation | The static status-list cache uses only the URI; decompression is unbounded; without trust certificates, signature verification is skipped. | Isolate cache entries by trust policy, bound decompression, and define signed-status trust for DID issuers. |

The `did:webvh` path validates signed history, required witnesses, current assertion keys and `kid`. Current-state resolution does not persist rollback checkpoints or consult watchers. See [its supported profile and limits](did-webvh.md).

## Reliable operation

- **Version policy:** select supported Keycloak/Java versions and test exact images. Upgrade runtime libraries separately from this cleanup.
- **Health checks:** the Coolify probe uses `curl` and `|| exit 0`, so it can report success without a healthy server. Replace it after validating the container's management endpoint.
- **Secrets and initialization:** the generic realm now omits application clients and verifier material, and starts with a disabled IdP. The image imports one selected realm file. Review the preserved OpenKYC example and remaining Compose credential defaults before deployment, and define verifier-key rotation and storage policy.
- **Clustering:** test replay races, node loss, cache invalidation, status polling across node changes, and rolling changes against the shared state store.
- **Observability:** structured errors, latency and resolution metrics, readiness, and logs without credential claims, presentations, or private material.
- **Resource limits:** test malformed and oversized presentations, DCQL complexity, request concurrency, and slow issuer endpoints.

## Before a public release

- Test a complete did:web wallet-to-Keycloak flow against the release image, in addition to cryptographic tests and the certificate-based E2E suite.
- Publish supported features and limitations. A passing happy path is not a conformance claim.
- Run the OIDF suite where applicable and document the profiles it validates.
- Maintain the private vulnerability route in [SECURITY.md](../SECURITY.md); define versioned support, signed releases, artifact inventory/SBOM, and dependency review cadence before public releases.
- Review tracked examples and the initial commit for private material. Keep required licenses and attribution in source and artifacts.

Suggested order: trust and login integrity, deployment reliability, runtime upgrades, then public release automation. This cleanup preserves behavior so these decisions can be reviewed independently.
