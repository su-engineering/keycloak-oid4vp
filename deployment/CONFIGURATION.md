# Keycloak OID4VP Auto-Configuration

This directory contains the automated configuration for Keycloak with OID4VP extension.

## What's Auto-Configured

### 1. Realm: openkyc-partners
- **Name**: OpenKYC Partners
- **Features**: Transient users enabled
- **User Profile**: Email, First Name, Last Name are NOT required

### 2. Identity Provider: OID4VP (oid4vp)
- **Display Name**: Sign in with Wallet
- **Client ID Scheme**: x509_san_dns
- **Response Mode**: direct_post
- **DID Resolution**: Enabled for did:web
- **Transient Users**: Enabled (no user accounts stored)
- **X.509 Certificate**: Auto-configured for JAR signing
- **DCQL Query**: Pre-configured for AgeOverEighteenCredentialSD

### 3. Keys
- **ECDSA Key**: Generated for OID4VP JAR signing (ES256)
- **Priority**: 100 (highest)

### 4. Authentication Flow
- **First Broker Login**: Review Profile step DISABLED
- Users login immediately after wallet verification

## Files

- `realm-import.json`: Complete realm configuration including OID4VP IdP
- `docker-compose.coolify.yml`: Docker Compose with volume mounts
- `Dockerfile`: Keycloak image with extension and transient-users feature

## First Deployment

On first startup, Keycloak will:
1. Import the realm with all configurations
2. Generate the ECDSA signing key
3. Enable the OID4VP identity provider
4. Configure user profile (email/firstname/lastname not required)

## Manual Steps (One-time after first deployment)

After the first deployment, you need to:

1. **Get the generated Key ID (kid)**:
   ```bash
   curl https://auth.staging.openkyc.org/realms/openkyc-partners/protocol/openid-connect/certs | jq .
   ```
   Look for the EC key with `kid` starting with your generated key.

2. **Update Wallet Configuration**:
   Add this kid to your wallet's trusted JWKS for JAR verification.

## Updating Configuration

To update the realm configuration:
1. Edit `realm-import.json`
2. Restart the Keycloak container
3. Keycloak will re-import on startup

## Environment Variables

Keycloak Admin:
- `KEYCLOAK_ADMIN`: admin (default)
- `KEYCLOAK_ADMIN_PASSWORD`: admin (default) - **CHANGE IN PRODUCTION**

Database:
- `KC_DB_USERNAME`: keycloak (default)
- `KC_DB_PASSWORD`: keycloak (default) - **CHANGE IN PRODUCTION**

## Security Notes

⚠️ **Production Deployment**:
- Change default admin password
- Change database password
- Use HTTPS certificates
- Rotate signing keys periodically
- Enable brute force protection
