# Migration and rollback

## Independent development baseline

The development version starts at `0.1.0-SNAPSHOT`, with Maven group `io.github.su-engineering` and Java package `io.github.suengineering.keycloak.oid4vp`.

The namespace changes Java class names. Code that imports these classes must update its imports and rebuild. Keycloak realm configuration uses stable provider IDs and does not require a namespace migration.

| Preserved contract | Value / behavior |
| --- | --- |
| Installed JAR | `keycloak-extension-oid4vp.jar` |
| Identity provider | `oid4vp` |
| Claim mappers | `oid4vp-user-attribute-mapper`, `oid4vp-user-session-mapper` |
| Login theme | `oid4vp`, with the deployed OpenKYC presentation |
| DID configuration | Existing keys and defaults, including opt-in `didResolutionEnabled` |
| Login state | Existing request handles, nonce binding, shared-store keys and JSON shape |
| Runtime pins | Root Compose / Maven: 26.5.5; Coolify Dockerfile: 26.5.4 |

The cleanup does not change verification logic, credential acceptance policy, realm import contents, or database settings. License notices are included in the provider JAR.

## Repository rename

The GitHub repository is `su-engineering/keycloak-oid4vp`; the checkout directory is `keycloak-oid4vp`. Update an existing clone's remote with:

```sh
git remote set-url origin https://github.com/su-engineering/keycloak-oid4vp.git
```

This changes repository naming only. The Maven artifact ID and installed JAR remain `keycloak-extension-oid4vp` and `keycloak-extension-oid4vp.jar` to preserve existing build and deployment integrations. Provider IDs, Java packages, and realm configuration are unchanged.

## Optional neutral theme

The provider also bundles `su-engineering`. Existing realm selections stay unchanged. Select it explicitly under **Realm settings → Themes → Login theme**; restore the previous selection to undo the appearance change. This does not migrate credential policy or login state. See [themes](themes.md) for the inherited form behavior and OpenKYC entry-path notes.

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

No automated Maven Central publishing or GitHub release workflow is enabled in this baseline.
