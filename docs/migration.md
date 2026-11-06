# Migration and rollback

This guide covers upgrading from `0.1.0-rc.1` to `0.2.0`. Read the whole checklist before upgrading: several trust rules are stricter, and a configuration that worked with `0.1.0-rc.1` can reject logins after the upgrade until it is adjusted.

## Upgrading from 0.1.0-rc.1: required actions

Work through every item, then test a complete wallet login in staging before promoting the build.

1. **Keycloak 26.8.x and the provider ID.** The extension now requires Keycloak 26.8.x, and its identity provider ID changes from `oid4vp` to `oid4vp-wallet`. Keep the realm alias `oid4vp`; only the provider ID changes. Run [`scripts/migrate-provider-id.sql`](../scripts/migrate-provider-id.sql) with Keycloak stopped. See [Provider ID rename and Keycloak 26.8](#provider-id-rename-and-keycloak-268).
2. **Signed trust lists.** A configured `trustListUrl` must be signed. Set `trustListSigningCertPem` to the certificate (or chain) that signs the trust list; an unsigned trust list is rejected. `trustListAllowUnsigned=true` exists for local tests only.
3. **did:web key authorization and URL layout.** The DID document `id` must equal the DID, only keys referenced in `assertionMethod` and controlled by the DID can sign, and a JOSE `kid` must name one of those keys. Path DIDs such as `did:web:issuer.example:tenant` now resolve to `https://issuer.example/tenant/did.json`. Issuers that still publish at `<path>/.well-known/did.json` need `didWebLegacyPathLayout=true` until they move the document.
4. **Anchored issuer keys.** A signing key resolved from `/.well-known/jwt-vc-issuer` metadata must carry an `x5c` chain anchored in the trust list; metadata keys without one are rejected. Issuers without a PKI must use did:web or did:webvh with an explicit `allowedIssuers` list. mDoc `issuerAuth` must carry an `x5chain` anchored in the trust list or a configured VICAL; there is no fallback to a directly trusted key.
5. **SD-JWT issuer certificate names the issuer.** The leaf certificate of an SD-JWT `x5c` chain must name the credential's `iss` value as a subjectAltName URI, or name the `iss` host as a subjectAltName dNSName. A presented `x5c` that fails validation, is revoked or does not name the issuer rejects the credential; it no longer falls back to issuer metadata or to trusted keys. The direct trusted-certificate fallback, used only when no `x5c` is presented, also requires the certificate to name the issuer. Check your issuer certificates before upgrading. For issuers that cannot reissue certificates in time, `x5cIssuerBinding=false` restores the previous behavior for that identity provider; combine it with `allowedIssuers`, because without the binding any certificate anchored in the trust list can sign for any issuer.
6. **Digital Credentials API origin.** The Digital Credentials API flow is new since `0.1.0-rc.1`. When you enable it, set `dcApiOrigin` to the origin that serves the login page (for example `https://login.example.com`) or set the realm Frontend URL. Without either, the button is not shown. The origin is never derived from request headers.
7. **Credential-supplied URLs on private networks.** Status list, did:web and issuer metadata URLs taken from a credential are not fetched from loopback, private or link-local addresses. If your issuers or status lists run on an internal network, set `allowPrivateNetworkFetch=true`. Trust list and VICAL URLs configured in the provider are not affected.
8. **Same-device `response_code`.** Same-device and Digital Credentials API completion URLs now carry a `response_code`, and Keycloak rejects completion without the matching code. Custom themes, scripts and reverse proxies must pass the full redirect URL through unchanged.
9. **Cross-device status polling and theme scripts.** The login page now polls `/cross-device/status` with short requests instead of holding a Server-Sent Events stream.
   - `sseTimeoutSeconds` and `ssePingIntervalSeconds` are removed. Delete them from realm JSON.
   - `ssePollIntervalMs` is replaced by `crossDevicePollIntervalMs`. The old key is still read when the new one is unset; rename it.
   - The theme script `oid4vp-cross-device-sse.js` is replaced by `oid4vp-cross-device-status.js`. Custom themes that copied the SSE script or its template markup must switch to the new script.
   - Themes that copied `oid4vp-dc-api.js` from a development build of `main`: the `/dc-api/request` response is now `{"state": ..., "requests": [{"protocol": ..., "data": ...}, ...]}`, and the page posts the chosen `protocol` back to `/dc-api/response`. Copy the current script.
10. **Error details.** Error pages and wallet error responses no longer include an error description; they carry only the error code. The reason is recorded in Keycloak's event log (`LOGIN_ERROR` events with `error` and `error_description` details). Enable login events for the realm if you rely on them for troubleshooting.
11. **Deployment files.** If you use the Compose files in this repository, `KEYCLOAK_ADMIN`/`KEYCLOAK_ADMIN_PASSWORD` are replaced by `KC_BOOTSTRAP_ADMIN_USERNAME`/`KC_BOOTSTRAP_ADMIN_PASSWORD`, and the Coolify file requires `KC_DB_PASSWORD` and `KC_BOOTSTRAP_ADMIN_PASSWORD` to be set. See [deployment](../deployment/README.md).
12. **In-flight logins.** Restart logins that were in progress during the upgrade.

Status List Token signatures are now always verified. A status list that cannot be verified against the trust list, or against the keys that verified the credential, rejects the login. See [Revocation](configuration.md#revocation-token-status-list).

## Provider ID rename and Keycloak 26.8

Keycloak 26.8 ships its own experimental OID4VP verifier under the ID `oid4vp` (feature `oid4vc-vp`). With the old ID, enabling that feature would make one of the two providers disappear. The new ID `oid4vp-wallet` lets both be installed side by side. The Admin Console lists this extension as **OID4VP (Wallet Login)**.

| Item | Change |
| --- | --- |
| Identity provider ID (`providerId`) | `oid4vp` → `oid4vp-wallet` |
| Realm alias, broker URLs, wallet `response_uri`, `kc_idp_hint=oid4vp` | Unchanged; keep the alias `oid4vp` |
| Mapper IDs | Unchanged (`oid4vp-user-attribute-mapper`, `oid4vp-user-session-mapper`) |
| Linked user identities | Unchanged |
| Keycloak runtime | 26.5.x → 26.8.x; Keycloak runs its own database migrations on first start |

Keycloak's Admin REST API cannot change an existing provider's ID, and deleting and recreating the provider would delete users' linked identities. Rename it in the database instead:

1. Stop Keycloak and back up its database.
2. Run [`scripts/migrate-provider-id.sql`](../scripts/migrate-provider-id.sql) against the Keycloak database, for example `psql "postgresql://keycloak@db.example:5432/keycloak" -v ON_ERROR_STOP=1 -f scripts/migrate-provider-id.sql`.
3. Install the new provider JAR built for your 26.8.x runtime and start Keycloak 26.8.x.
4. Open **Identity providers → oid4vp** and confirm the settings and mappers load.

For realm JSON exports that you import, replace `"providerId": "oid4vp"` with `"providerId": "oid4vp-wallet"` before importing. Leave `"alias": "oid4vp"` as it is.

Do not run the script if you have enabled Keycloak's native `oid4vc-vp` feature and created native OID4VP providers, because those rows would be renamed too.

## Rollback

Keycloak's schema migrations are not reversible, so rollback means restoring the backup:

1. Stop Keycloak 26.8.x.
2. Restore the database backup taken before the upgrade. The script's header also shows the reverse `UPDATE`, but restoring the backup is the supported path because Keycloak 26.8 has already migrated the schema.
3. Redeploy the `0.1.0-rc.1` JAR on the previous Keycloak 26.5.x image, together with the previous realm configuration.

Rehearse this restoration in staging before upgrading production.

## Deploying a reviewed build

1. Record and retain the running image digest. Back up the database and realm configuration using the deployment's existing backup process.
2. Test the candidate in an isolated environment with the same Keycloak version and equivalent realm configuration. Use synthetic credentials or an authorized test issuer.
3. Work through the [required actions](#upgrading-from-010-rc1-required-actions), then exercise did:web SD-JWT login, same-device and cross-device completion, the Digital Credentials API if enabled, expiry and revocation rejection, and the X.509 paths used by the deployment.
4. Replace the provider JAR at the existing path and run Keycloak's build step. Install only one copy of the provider: old and new builds register the same mapper IDs and theme names.
5. Validate staging before promotion. Allow in-flight logins to finish or restart them during rollout.

## Runtime upgrades

The current Keycloak pins (26.8.0 and 26.8.1 in CI, 26.8.1 for the Compose files and Maven default) are a compatibility baseline, not a long-term support commitment. Moving to a newer Keycloak line requires:

- A separate dependency and API review, especially the internal SD-JWT and private SPI APIs.
- Matching compile and container versions for each tested runtime.
- Regression coverage using the deployed did:web credential shape and wallet flows.
- Staging, database migration rehearsal, and image/database rollback.

Versioned tags publish runtime-specific JARs and checksums through the [GitHub release workflow](releases.md). Maven Central publishing is not enabled.

## Earlier changes included in 0.1.0-rc.1

The sections below describe changes that `0.1.0-rc.1` already contains. They matter only when upgrading from a build older than that tag.

### Package namespace

Maven group `io.github.su-engineering` and Java package `io.github.suengineering.keycloak.oid4vp`. Code that imports these classes must update its imports and rebuild. The installed JAR is still `keycloak-extension-oid4vp.jar`.

### OpenKYC theme rename and generic realm

The OpenKYC login theme is now `openkyc`. Before replacing the old JAR, record each realm and client-level login theme override using `oid4vp`. After installing the new build, set those selections to `openkyc` in the Admin Console (realm: **Realm settings → Themes**; client override: **Clients → client → Login settings**). For rollback to an older JAR, restore the theme selection to `oid4vp`. The theme rename does not change the IdP alias `oid4vp`, mapper IDs, broker URLs, or `kc_idp_hint=oid4vp`.

`deployment/realm-import.json` creates a generic `wallet` realm using `su-engineering` and direct wallet entry through `wallet-browser`. Its provider starts disabled until configured in the Admin Console. It contains no application clients, issuer allowlists, credential query, or verifier certificates. Setup is documented in [installation](installation.md#configure-a-realm).

The previous OpenKYC import is retained at `deployment/examples/realm-openkyc.json`, with `loginTheme` set to `openkyc`. For an existing OpenKYC deployment, set `OID4VP_REALM_IMPORT=deployment/examples/realm-openkyc.json` in Coolify to avoid importing an additional `wallet` realm on the next build. Existing database-backed realms are skipped by startup import; update their theme and settings in the Admin Console. Keep their existing credential policy and `oid4vp-browser` binding.

The Dockerfile imports one selected file and does not generate verifier keys or certificates during the image build. New generic deployments configure that material through **Identity providers → oid4vp**.

The provider also bundles the neutral `su-engineering` theme. Select it under **Realm settings → Themes → Login theme**. See [themes](themes.md).

### DCQL validation and multi-credential verification

Manual DCQL JSON is structurally validated on provider creation, import, and Admin Console/API updates. Malformed queries must be corrected before saving; clearing the field selects mapper-derived requests. See [DCQL editing and current response-policy limits](dcql.md).

Responses enforce query ID, format/type, required sets, claim paths and exact `values`, so wallets that return incomplete or mismatched credentials fail. Query IDs must use letters, numbers, underscores or hyphens; put type URIs or mDoc doctypes in `meta`, not the ID.

Use presentation arrays in JSON `vp_token` entries. Bare tokens remain supported only when one query ID is possible. Configure **Identity Credential Query ID** for multi-credential logins and scope mappers by query ID or type. Scalar mappings that match multiple presentations reject ambiguity. Multi-valued session-note arrays retain all values as JSON. Unbound credential requests are rejected, and mDoc login requires device authentication and one document per DeviceResponse. See [multi-credential setup](multiple-credential-types.md#require-several-credentials-in-one-login).

### DID method enforcement and did:webvh

`did:webvh` is opt-in: enable DID resolution (`didResolutionEnabled`) and add `did:webvh` to **Allowed DID Methods**. The default remains `did:web`. See [the WebVH guide](did-webvh.md).

**Allowed DID Methods** is enforced. When DID resolution is enabled, disallowed or unsupported DID issuers and resolution failures reject the presentation instead of falling back to certificates or issuer metadata. WebVH credentials cannot bypass history verification by attaching an X.509 certificate, including when DID resolution is disabled.

### Repository rename

The GitHub repository is `su-engineering/keycloak-oid4vp`. Update an existing clone's remote with:

```sh
git remote set-url origin https://github.com/su-engineering/keycloak-oid4vp.git
```

The Maven artifact ID and installed JAR remain `keycloak-extension-oid4vp` and `keycloak-extension-oid4vp.jar`.
