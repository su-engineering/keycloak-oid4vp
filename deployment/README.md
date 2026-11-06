# Coolify deployment

This directory builds Keycloak **26.8.1** with PostgreSQL and TLS termination at Coolify's reverse proxy. New installations import the generic `wallet` realm. Complete provider and client configuration in the [Admin Console](../docs/installation.md#configure-a-realm).

The JAR contains `su-engineering` and `openkyc`. Direct wallet entry is configured by the realm authentication flow. Existing OpenKYC deployments must select `openkyc` after upgrading; the IdP alias remains `oid4vp`. See [migration](../docs/migration.md#openkyc-theme-rename-and-generic-realm).

Existing deployments upgrading from `0.1.0-rc.1` must stop Keycloak, back up the database and run [`scripts/migrate-provider-id.sql`](../scripts/migrate-provider-id.sql) before starting the new build, because the identity provider ID changes from `oid4vp` to `oid4vp-wallet`. Work through the [upgrade checklist](../docs/migration.md#upgrading-from-010-rc1-required-actions) for the other required changes.

## Files

| File | Purpose |
| --- | --- |
| [docker/Dockerfile](docker/Dockerfile) | Maven build, selected realm import, and optimized Keycloak runtime |
| [docker-compose.coolify.yml](docker-compose.coolify.yml) | Keycloak, PostgreSQL, and external `coolify` network |
| [realm-import.json](realm-import.json) | Generic realm with direct wallet entry; configure and enable its IdP in the Admin Console |
| [examples/realm-openkyc.json](examples/realm-openkyc.json) | Existing OpenKYC realm and credential policy, selecting `openkyc` |
| [.env.example](.env.example) | Environment variable names and example values |

## Review before deploying

These are compatibility files, not hardened production defaults:

- The Compose file has no default database or admin password. `KC_DB_PASSWORD` and `KC_BOOTSTRAP_ADMIN_PASSWORD` must be set through the deployment platform, otherwise Compose refuses to start.
- The current healthcheck ends with `|| exit 0`; it can report success when Keycloak is unavailable.
- The generic import starts with a disabled IdP. Configure verifier signing material, credential requests, issuer trust, and application clients in the Admin Console before enabling it.
- The OpenKYC example preserves deployment-specific settings and its verifier certificate; review them before reusing it for a new environment.
- Startup import initializes absent realms; it is not a general migration mechanism for an existing realm.
- The external `coolify` Docker network and proxy labels assume a Coolify-managed environment.

These items are tracked in [enterprise readiness](../docs/enterprise-readiness.md). The Dockerfile imports exactly one selected file; it does not generate verifier material at build time.

## Build and inspect locally

Run from the repository root:

```sh
./mvnw clean verify -Dkeycloak.version=26.8.1
docker compose --project-directory . -f deployment/docker-compose.coolify.yml config --quiet
docker build -f deployment/docker/Dockerfile -t keycloak-oid4vp:review .
```

The build copies exactly one provider JAR: `/opt/keycloak/providers/keycloak-extension-oid4vp.jar`. The Dockerfile compiles with the Maven default (26.8.1) and runs on 26.8.1. Upgrading an existing 26.5.x deployment runs Keycloak's database migrations: back up the database first and follow [migration](../docs/migration.md).

## Configure Coolify

1. Connect the organization repository to a Docker Compose application.
2. Select `deployment/docker-compose.coolify.yml` and use the repository root as the build/project directory.
3. Configure the external hostname, TLS, and proxy routing in Coolify.
4. Supply explicit database and bootstrap credentials through protected environment variables.
5. Set `OID4VP_REALM_IMPORT=deployment/realm-import.json` for a new generic deployment, or `deployment/examples/realm-openkyc.json` for OpenKYC. The selected file is copied during image construction.
6. Build a reviewed revision, then complete configuration in the Admin Console. Startup import skips realms already present in the database.

| Variable | Role |
| --- | --- |
| `OID4VP_REALM_IMPORT` | Build-time realm source path; defaults to `deployment/realm-import.json` |
| `KC_DB_URL` | JDBC URL, normally `jdbc:postgresql://postgres:5432/keycloak` |
| `KC_DB_USERNAME` | Database user shared with PostgreSQL initialization |
| `KC_DB_PASSWORD` | Database password; required |
| `KC_BOOTSTRAP_ADMIN_USERNAME` | Temporary bootstrap admin user, created only when the master realm has no admin; defaults to `admin` |
| `KC_BOOTSTRAP_ADMIN_PASSWORD` | Bootstrap admin password; required |
| `SERVICE_URL_KEYCLOAK` | Public URL set by Coolify; passed to `KC_HOSTNAME` and `KC_HOSTNAME_ADMIN` |
| `SERVICE_FQDN_KEYCLOAK_8080` | Coolify routing variable for port 8080 |

`KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD` are deprecated in Keycloak 26, and the hostname v1 options `KC_HOSTNAME_URL` and `KC_HOSTNAME_ADMIN_URL` were removed. The Compose file uses the replacements above. Deployments that set the old variable names in Coolify must rename them.

Confirm values in the rendered Compose configuration privately. Full `docker compose config` output may contain secrets; `config --quiet` checks structure without printing them.

## Validate and update

Check startup/database errors, actual readiness, provider registration, realm keys, selected login theme, and a complete synthetic wallet login through the public hostname. Exercise did:web SD-JWT credentials, both device flows, and the issuer/revocation policies used by the deployment.

Retain the running image digest and database/realm backup before promotion. Coolify may rebuild automatically when its configured branch changes; branch pushes are deployment events if that integration is enabled.

Changing the Dockerfile image tag alone is not a validated runtime upgrade. Follow [migration and rollback](../docs/migration.md), test the candidate runtime and database migration, and rehearse restoration.

## Troubleshooting

Start with [operations](../docs/operations.md). For deployment-specific failures, inspect database connectivity, Coolify network membership, the configured external scheme/host, and the final realm import contents. A green Compose health status is insufficient with the current probe.
