# Coolify deployment

This directory builds Keycloak **26.5.4** with PostgreSQL and TLS termination at Coolify's reverse proxy. New installations import the generic `wallet` realm. Complete provider and client configuration in the [Admin Console](../docs/installation.md#configure-a-realm).

The JAR contains `su-engineering` and `openkyc`. Direct wallet entry is configured by the realm authentication flow. Existing OpenKYC deployments must select `openkyc` after upgrading; the IdP alias remains `oid4vp`. See [migration](../docs/migration.md#openkyc-theme-rename-and-generic-realm).

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

- The Compose file has fallback database/admin credentials. Set explicit secrets through the deployment platform.
- The current healthcheck ends with `|| exit 0`; it can report success when Keycloak is unavailable.
- The generic import starts with a disabled IdP. Configure verifier signing material, credential requests, issuer trust, and application clients in the Admin Console before enabling it.
- The OpenKYC example preserves deployment-specific settings and its verifier certificate; review them before reusing it for a new environment.
- Startup import initializes absent realms; it is not a general migration mechanism for an existing realm.
- The external `coolify` Docker network and proxy labels assume a Coolify-managed environment.

These items are tracked in [enterprise readiness](../docs/enterprise-readiness.md). The Dockerfile imports exactly one selected file; it does not generate verifier material at build time.

## Build and inspect locally

Run from the repository root:

```sh
./mvnw clean verify -Dkeycloak.version=26.5.4
docker compose --project-directory . -f deployment/docker-compose.coolify.yml config --quiet
docker build -f deployment/docker/Dockerfile -t keycloak-oid4vp:review .
```

The build copies exactly one provider JAR: `/opt/keycloak/providers/keycloak-extension-oid4vp.jar`. The current Dockerfile compiles with the Maven default (26.5.5) and runs on 26.5.4; the test matrix covers both. A future runtime upgrade must align build and deployment choices deliberately.

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
| `KC_DB_PASSWORD` | Database password; supply an explicit secret |
| `KEYCLOAK_ADMIN` | Existing bootstrap admin variable used by this Compose file |
| `KEYCLOAK_ADMIN_PASSWORD` | Existing bootstrap admin password variable; supply an explicit secret |
| `SERVICE_FQDN_KEYCLOAK` / `SERVICE_URL_KEYCLOAK` | Hostname and URL values used by the Coolify configuration |

Confirm values in the rendered Compose configuration privately. Full `docker compose config` output may contain secrets; `config --quiet` checks structure without printing them.

## Validate and update

Check startup/database errors, actual readiness, provider registration, realm keys, selected login theme, and a complete synthetic wallet login through the public hostname. Exercise did:web SD-JWT credentials, both device flows, and the issuer/revocation policies used by the deployment.

Retain the running image digest and database/realm backup before promotion. Coolify may rebuild automatically when its configured branch changes; branch pushes are deployment events if that integration is enabled.

Changing the Dockerfile image tag alone is not a validated runtime upgrade. Follow [migration and rollback](../docs/migration.md), test the candidate runtime and database migration, and rehearse restoration.

## Troubleshooting

Start with [operations](../docs/operations.md). For deployment-specific failures, inspect database connectivity, Coolify network membership, the configured external scheme/host, final realm import contents, and proxy handling of the SSE stream. A green Compose health status is insufficient with the current probe.
