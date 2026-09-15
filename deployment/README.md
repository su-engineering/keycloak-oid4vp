# Keycloak OID4VP Extension - Coolify Deployment

## Overview

This directory contains all files needed to deploy Keycloak with the OID4VP extension to Coolify.

**Features:**
- Keycloak 26.5.4 with OID4VP identity provider
- PostgreSQL database for persistence
- OpenKYC custom theme
- Auto-imported realm configuration
- SSL handled by Coolify reverse proxy

## Prerequisites

- Coolify instance with Docker runtime
- VPS with Docker support
- Domain name (optional, but recommended)

## File Structure

```
deployment/
├── docker/
│   └── Dockerfile           # Multi-stage build (Maven + Keycloak)
├── scripts/
│   └── generate-realm.sh    # Realm certificate generation
├── docker-compose.coolify.yml  # Full stack definition
├── .env.example             # Environment variable template
└── README.md                # This file
```

## Deployment Steps

### 1. Prepare Your Repository

After validating the candidate and coordinating deployment, push your reviewed branch to the organization repository. A push to the configured deployment branch may trigger a rebuild:
```bash
git push origin main
```

### 2. Create Coolify Resource

1. Log in to your Coolify dashboard
2. Click **Add New Resource**
3. Select **Application** (or use Docker Compose)
4. Choose **Docker Compose** as the source
5. Connect your GitHub repository
6. Select the `deployment/docker-compose.coolify.yml` file

### 3. Configure Environment Variables

In Coolify, go to the **Environment Variables** section and add:

| Variable | Required | Description |
|----------|----------|-------------|
| `KC_DB_URL` | Yes | `jdbc:postgresql://postgres:5432/keycloak` |
| `KC_DB_USERNAME` | Yes | Database username (e.g., `keycloak`) |
| `KC_DB_PASSWORD` | Yes | Database password |
| `KEYCLOAK_ADMIN` | No | Admin username (default: `admin`) |
| `KEYCLOAK_ADMIN_PASSWORD` | Yes | Admin password |

### 4. Deploy

Click **Deploy** in Coolify.

The first deployment will:
1. Build the Keycloak extension with Maven
2. Generate realm certificates
3. Build the optimized Keycloak image
4. Start PostgreSQL and Keycloak

### 5. Verify Deployment

After deployment completes:

1. **Check Health**: inspect Keycloak startup and readiness. The current Compose healthcheck suppresses failures; a green Coolify status alone is not sufficient.
2. **Access Admin Console**: `https://your-domain/admin`
3. **Login**: Use your `KEYCLOAK_ADMIN` credentials

## Post-Deployment

### Verify Realm Imported

1. Go to **Realm Settings** → **Keys**
2. Verify signing keys are present
3. Go to **Identity Providers**
4. Verify **oid4vp** provider is configured

### Verify Theme Active

1. Go to **Realm Settings** → **Themes**
2. Verify **Login Theme** is set to `oid4vp`

### Test OID4VP Flow

1. Access the Keycloak login page
2. You should see "Sign in with Wallet" option
3. Clicking it should redirect to wallet authentication

## Updating

### Update the extension

Build from this repository and test the change with `./mvnw clean verify`. Review [migration and rollback](../docs/migration.md) before changing a deployed image. This is an independent project; no external repository synchronization is required.

Coolify can automatically rebuild on pushes to its configured branch. Keep unreviewed changes on a development branch until staging validation is complete.

### Update Keycloak Version

Edit `deployment/docker/Dockerfile` and update the Keycloak version:
```dockerfile
FROM quay.io/keycloak/keycloak:NEW_VERSION
```

## Troubleshooting

### Build Fails: Maven Dependencies

**Symptom**: Build fails during `mvn package`

**Solution**: use Java 21 and the pinned Maven wrapper; confirm the compile target matches the Keycloak version being tested.

### Keycloak Won't Start

**Symptom**: Container exits immediately

**Solution**: Check logs for database connection errors. Verify:
- `KC_DB_URL` is correct
- Database credentials match between Keycloak and PostgreSQL

### Realm Not Imported

**Symptom**: OID4VP identity provider not visible

**Solution**: 
1. Check logs for realm import errors
2. Verify realm JSON is in `/opt/keycloak/data/import/`
3. Check certificate generation succeeded

### SSL Certificate Issues

**Symptom**: Browser shows certificate warning

**Solution**: Coolify handles SSL. Check:
1. Domain is properly configured in Coolify
2. DNS points to Coolify server
3. Wait for SSL certificate to provision (may take a few minutes)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Coolify (Reverse Proxy + SSL)                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Docker Network                                        │  │
│  │                                                        │  │
│  │  ┌──────────────┐  ┌────────────────────────────┐   │  │
│  │  │  PostgreSQL  │  │  Keycloak + OID4VP Ext      │   │  │
│  │  │  :5432       │  │  :8080                       │   │  │
│  │  │              │  │  - openkyc-partners realm    │   │  │
│  │  │              │  │  - OID4VP IdP configured     │   │  │
│  │  └──────────────┘  └────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## License

This deployment configuration is part of the [keycloak-extension-oid4vp](https://github.com/su-engineering/keycloak-extension-oid4vp) project.

## Existing deployment compatibility

The Dockerfile remains on Keycloak 26.5.4; the Maven/root Compose baseline is 26.5.5. CI tests both versions. The image build copies exactly one provider JAR and uses the checked-in Maven wrapper.

These files describe the existing OpenKYC deployment, not hardened defaults for an arbitrary production installation. Example credentials, realm import initialization, signing-key storage, and the healthcheck need review before public distribution; see [enterprise readiness](../docs/enterprise-readiness.md).

When running this nested Compose file directly from a checkout, use the repository root as the project directory:

```sh
docker compose --project-directory . -f deployment/docker-compose.coolify.yml config --quiet
```
