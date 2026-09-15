#!/bin/sh
# Generate realm JSON with self-signed cert for OIDC4VP IdP
set -e

OUT_DIR="${1:-.}"
DOMAIN="${2:-localhost}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Generate self-signed EC cert
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -out key_pkcs8.pem

# Create cert config
cat > cert.conf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = ${DOMAIN}
[v3_req]
keyUsage = digitalSignature, keyCertSign
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
EOF

openssl req -new -x509 -key key.pem -out cert.pem -days 365 -config cert.conf

# Combined PEM
cat cert.pem key_pkcs8.pem > combined.pem

# Escape for JSON
PEM_ESCAPED=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' combined.pem | sed 's/\\n$//')

# DCQL query
DCQL='{"credentials":[{"id":"age_over_18","format":"jwt_vc_json","meta":{"vct_values":["AgeOverEighteenCredential"]},"claims":[{"path":["ageOverEighteen"],"values":[true]}]}]}'
DCQL_ESCAPED=$(printf '%s' "$DCQL" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')

# Generate realm JSON
cat > realm-openkyc-partners.json <<REALM_EOF
{
  "realm": "openkyc-partners",
  "enabled": true,
  "displayName": "OpenKYC Partners",
  "registrationAllowed": false,
  "clients": [
    {
      "clientId": "partner-demo",
      "enabled": true,
      "publicClient": true,
      "redirectUris": ["http://localhost:3000/*", "http://localhost:*/*"],
      "webOrigins": ["+"],
      "protocol": "openid-connect",
      "standardFlowEnabled": true,
      "attributes": {
        "pkce.code.challenge.method": "S256"
      }
    }
  ],
  "identityProviders": [
    {
      "alias": "oid4vp",
      "displayName": "Sign in with Wallet",
      "providerId": "oid4vp",
      "enabled": true,
      "config": {
        "clientIdScheme": "x509_san_dns",
        "x509CertificatePem": "${PEM_ESCAPED}",
        "walletScheme": "openid4vp://",
        "enforceHaip": "false",
        "dcqlQuery": "${DCQL_ESCAPED}",
        "allowedIssuers": "*",
        "allowedCredentialTypes": "*",
        "sameDeviceEnabled": "true",
        "crossDeviceEnabled": "true",
        "userMappingClaim": "sub"
      }
    }
  ]
}
REALM_EOF

rm -f key.pem key_pkcs8.pem cert.pem combined.pem cert.conf

# Validate JSON
jq empty realm-openkyc-partners.json
echo "Generated: realm-openkyc-partners.json"