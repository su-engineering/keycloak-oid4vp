# Operations and troubleshooting

This guide describes the current implementation and the evidence to collect when a login fails. It is not an enterprise support or availability guarantee; see [readiness](enterprise-readiness.md).

## Record the deployed baseline

Keep the image digest, extension revision/JAR checksum, Keycloak version, realm configuration, proxy configuration, and database backup together. The root Compose file uses 26.5.5; the existing Coolify Dockerfile uses 26.5.4. Check the image actually running before choosing a build target.

Treat provider aliases, mapper IDs, claim names, and issuer policy as application contracts. [Migration and rollback](migration.md) lists the stable identifiers and staging checks.

## Diagnose by symptom

| Symptom | Likely area | Next check |
| --- | --- | --- |
| Provider is absent | Packaging or image build | Check there is one provider JAR in `providers/`, rebuild Keycloak, and inspect startup logs. |
| Class or method not found | Keycloak version mismatch | Compare the compile target and runtime image; run the matching test matrix. |
| New theme is absent or stale | Realm selection or caching | Select `su-engineering` in the correct realm, start a fresh login, and clear the theme cache through your normal deployment process. |
| Wallet will not open | URI handler | Confirm the configured `walletScheme` and installed wallet; use the included demo wallet for local testing. |
| Phone cannot read the request | Reachability or HTTPS | The phone and wallet backend must reach `request_uri`; a `localhost` URL points at the phone itself. |
| Issuer key cannot be resolved | DID, certificate, or metadata policy | Check `iss`, the DID document URL/key representation, TLS reachability, trust list, and configured fallback mode. |
| Signature or holder binding fails | Credential or transaction mismatch | Check the signing key, disclosure integrity, nonce, audience, and clock. Do not disable verification to suppress the error. |
| User cannot be identified | Claim mapping | Confirm the requested identifying claim is disclosed, or use explicitly configured transient-user mode. |
| Credential rejected as revoked | Status policy | Check the credential's status reference, the returned status token, trust configuration, and cache freshness. |
| Wallet succeeds, browser keeps waiting | SSE/proxy/session | Check the status stream, completion event, browser cookies, and shared store. |
| Session mismatch or expired request | Browser binding or timeout | Return in the initiating browser profile; start a fresh attempt after expiry. |

## Cross-device completion

The browser subscribes to a server-sent event stream. The wallet's callback stores a completion marker in Keycloak's shared single-use object store. An SSE worker polls the store and sends a `complete` event with the return URL.

Check each boundary in order:

1. **Wallet callback:** did Keycloak accept the presentation? A QR scan or a wallet's local success message alone is insufficient.
2. **Shared state:** can all relevant Keycloak nodes read the same single-use objects and authentication session?
3. **Proxy:** does it pass streaming responses promptly, preserve cookies and the external scheme/host, and allow the configured connection lifetime?
4. **Browser:** did the SSE connection open and receive a `complete` event? Did navigation retain the initiating authentication session?
5. **Completion:** did `/complete-auth` consume the deferred identity and continue the broker flow?

Do not expose an unauthenticated completion endpoint or bypass the session-cookie check to repair a proxy issue. The [protocol diagram](diagrams.md#login-and-completion) shows the normal flow; [configuration](configuration.md#cross-device-sse) lists timeout and polling settings.

## Logs and support reports

Use normal informational logging outside a controlled diagnostic session. The root development Compose file enables trace logging for the extension; it is not a production logging policy. Wallet and integration-test logs can contain presentations and synthetic credential claims.

For a bug report, include:

- The extension revision, Keycloak/Java versions, and deployment topology.
- Same-device or cross-device flow; SD-JWT or mDoc; did:web or certificate issuer.
- Expected and actual behavior, with a minimal synthetic reproduction.
- Relevant error names, timestamps, and redacted configuration.

Remove private keys, tokens, cookies, full presentations, personal claims, and live request handles. Send security-sensitive reports through [SECURITY.md](../SECURITY.md).

## Trust and cache changes

Issuer trust and verifier authentication are separate. The certificate identifying the verifier to a wallet does not authorize every credential issuer. DID resolution is also not a substitute for an issuer allow-list or signed status policy.

Before rotating keys or changing cache settings, test both overlap and removal scenarios with the deployed credential shape. The current DID resolver caches within resolver instances; the status-list cache is shared by URI. Cache isolation and bounded network access are outstanding [readiness work](enterprise-readiness.md), so do not assume tenant-independent trust from the cache alone.

## Health and rollout

The existing Coolify healthcheck suppresses failures and must not be used as sole evidence of readiness. Verify actual Keycloak readiness, database connectivity, provider startup, and a complete synthetic wallet login. A future healthcheck change should test the runtime's actual management endpoint and container tooling.

Promote a tested immutable image, preserve the previous image and database/realm backup, and let in-flight logins finish or restart them during rollout. Rehearse runtime/database upgrades separately from theme changes. See [migration](migration.md) for the release validation and rollback procedure.
