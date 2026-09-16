# Migration and rollback

## Independent development baseline

The development version starts at `0.1.0-SNAPSHOT`, with Maven group `io.github.su-engineering` and Java package `io.github.suengineering.keycloak.oid4vp`.

The namespace changes Java class names. Code that imports these classes must update its imports and rebuild. Keycloak realm configuration uses stable provider IDs and does not require a namespace migration.

| Preserved contract | Value / behavior |
| --- | --- |
| Installed JAR | `keycloak-extension-oid4vp.jar` |
| Identity provider | `oid4vp` |
| Claim mappers | `oid4vp-user-attribute-mapper`, `oid4vp-user-session-mapper` |
| OpenKYC login theme | Renamed from `oid4vp` to `openkyc`; update the realm selection |
| DID configuration | Existing keys and defaults, including opt-in `didResolutionEnabled` |
| Login state | Existing request handles and nonce binding; new requests additionally save full DCQL and identity-query selection |
| Runtime pins | Root Compose / Maven: 26.5.5; Coolify Dockerfile: 26.5.4 |

The namespace cleanup did not change verification logic or credential acceptance policy. License notices are included in the provider JAR. The subsequent realm and theme changes below require explicit configuration updates.

## OpenKYC theme rename and generic realm

The OpenKYC login theme is now `openkyc`. Before replacing the old JAR, record each realm and client-level login theme override using `oid4vp`. After installing the new build, set those selections to `openkyc` in the Admin Console (realm: **Realm settings → Themes**; client override: **Clients → client → Login settings**). For rollback to an older JAR, restore the theme selection to `oid4vp`. Do not rename the IdP alias/provider ID, mapper IDs, broker URLs, or `kc_idp_hint=oid4vp`.

`deployment/realm-import.json` now creates a generic `wallet` realm using `su-engineering` and direct wallet entry through `wallet-browser`. Its provider starts disabled until configured in the Admin Console. It contains no application clients, issuer allowlists, credential query, or verifier certificates. Setup is documented in [installation](installation.md#configure-a-realm).

The previous OpenKYC import is retained at `deployment/examples/realm-openkyc.json`, with `loginTheme` changed to `openkyc`. For an existing OpenKYC deployment, set `OID4VP_REALM_IMPORT=deployment/examples/realm-openkyc.json` in Coolify to avoid importing an additional `wallet` realm on the next build. Existing database-backed realms are skipped by startup import; update their theme and settings in the Admin Console. Keep their existing credential policy and `oid4vp-browser` binding.

The Dockerfile imports one selected file and no longer generates verifier keys or certificates during the image build. New generic deployments configure that material through **Identity providers → oid4vp**. Existing OpenKYC deployments already used the static import that overwrote the generated file.

Manual DCQL JSON is now structurally validated on provider creation, import, and Admin Console/API updates. Previously accepted malformed queries must be corrected before saving; clearing the field selects mapper-derived requests. The saved query and its conditions are preserved. See [DCQL editing and current response-policy limits](dcql.md).

## DID method enforcement and did:webvh

`did:webvh` is opt-in: enable DID resolution and add `did:webvh` to **Allowed DID Methods**. The default remains `did:web`. See [the WebVH guide](did-webvh.md).

**Allowed DID Methods is now enforced.** When DID resolution is enabled, disallowed or unsupported DID issuers and resolution failures reject the presentation instead of falling back to certificates or issuer metadata. Review existing values and issuer reachability before upgrading. For example, a provider configured with only `did:webvh` will reject `did:web` issuers. WebVH credentials cannot bypass history verification by attaching an X.509 certificate, including when DID resolution is disabled. HTTPS issuer certificate/metadata verification is unchanged.

The legacy did:web document/key and URL behavior remains otherwise unchanged. WebVH uses its own stricter resolver and only current assertion keys.

## Repository rename

The GitHub repository is `su-engineering/keycloak-oid4vp`; the checkout directory is `keycloak-oid4vp`. Update an existing clone's remote with:

```sh
git remote set-url origin https://github.com/su-engineering/keycloak-oid4vp.git
```

This changes repository naming only. The Maven artifact ID and installed JAR remain `keycloak-extension-oid4vp` and `keycloak-extension-oid4vp.jar` to preserve existing build and deployment integrations. Provider IDs, Java packages, and realm configuration are unchanged.

## Optional neutral theme

The provider also bundles `su-engineering`. Select it explicitly under **Realm settings → Themes → Login theme**; select `openkyc` for the OpenKYC appearance. Existing selections are not migrated automatically, so update any `oid4vp` theme selections as described above. Theme selection does not migrate credential policy or login state. See [themes](themes.md) for direct wallet entry and inherited form behavior.

## Deploying a reviewed build

1. Record and retain the running image digest. Back up the database and realm configuration using the deployment's existing backup process.
2. Test the candidate in an isolated environment with the same Keycloak version and equivalent realm configuration. Use synthetic credentials or an authorized test issuer.
3. Exercise did:web SD-JWT login, same-device and cross-device completion, expiry/revocation rejection, and the X.509 paths used by the deployment.
4. Replace the provider JAR at the existing path and run Keycloak's build step. Do not install both namespace versions together; they register identical provider IDs.
5. Validate staging before promotion. Allow in-flight logins to finish or restart them during rollout.

For rollback on the unchanged runtime, restore the retained image and configuration. Changing Java packages alone does not require a database migration. A later Keycloak upgrade may migrate the database; follow that version's migration guidance and rehearse restoration before upgrading.

## Runtime upgrades

The current pins are a compatibility baseline, not a long-term support commitment. Moving to a newer Keycloak line requires:

- A separate dependency and API review, especially the internal SD-JWT and private SPI APIs.
- Matching compile and container versions for each tested candidate.
- Regression coverage using the deployed did:web credential shape and wallet flows.
- An explicit decision about stricter DID trust checks and any migration of HAIP/SIOP settings.
- Staging, database migration rehearsal, and image/database rollback.

Versioned tags now publish runtime-specific JARs and checksums through the [GitHub release workflow](releases.md). Maven Central publishing is not enabled.

## DCQL multi-credential verification

Start fresh login flows after upgrading: old in-flight request contexts without a saved DCQL query are rejected. Responses now enforce query ID, format/type, required sets, claim paths and exact `values`, so wallets that previously returned incomplete or mismatched credentials can fail. Review existing manual queries and test your wallet before rollout. Query IDs must use letters, numbers, underscores or hyphens; put type URIs or mDoc doctypes in `meta`, not the ID.

Use presentation arrays in JSON `vp_token` entries. Bare tokens remain supported only when one query ID is possible. Configure **Identity Credential Query ID** for multi-credential logins and scope mappers by query ID or type. Scalar mappings that match multiple presentations now reject ambiguity. Multi-valued session-note arrays now retain all values as JSON instead of selecting the first value. Unbound credential requests are rejected, and mDoc login requires device authentication and one document per DeviceResponse. Explicit `meta` objects are preserved; legacy inference applies only when `meta` is omitted.

See [multi-credential setup](multiple-credential-types.md#require-several-credentials-in-one-login).
