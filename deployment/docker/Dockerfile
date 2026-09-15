# Stage 1: Build OIDC4VP extension with Maven
FROM maven:3.9-eclipse-temurin-21-alpine AS builder
WORKDIR /build

# Copy pom.xml first for caching
COPY pom.xml .
COPY mvnw .
COPY .mvn ./.mvn
COPY LICENSE NOTICE ./
COPY src ./src

RUN ./mvnw --batch-mode --no-transfer-progress clean package -DskipTests

# Stage 2: Realm Builder - Generate realm JSON with certificates
FROM alpine:3.21 AS realm-builder
RUN apk add --no-cache openssl jq
WORKDIR /realm

# Accept domain argument or default to localhost
ARG OID4VP_DOMAIN=localhost
ENV OID4VP_DOMAIN=${OID4VP_DOMAIN}

COPY deployment/scripts/generate-realm.sh /generate-realm.sh
RUN chmod +x /generate-realm.sh && /generate-realm.sh /realms ${OID4VP_DOMAIN}

# Stage 3: Runtime - Keycloak with extension
FROM quay.io/keycloak/keycloak:26.5.4

# Set build-time environment variables (must be set before kc.sh build)
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_HTTP_ENABLED=true
ENV KC_HOSTNAME_STRICT=false
ENV KC_PROXY=edge
ENV KC_FEATURES=transient-users

# Copy providers from builder
COPY --from=builder /build/target/keycloak-extension-oid4vp.jar /opt/keycloak/providers/keycloak-extension-oid4vp.jar

# Copy realm JSON from builder and custom realm import
COPY --from=realm-builder /realms/*.json /opt/keycloak/data/import/
COPY deployment/realm-import.json /opt/keycloak/data/import/realm-openkyc-partners.json

# Build optimized Keycloak image with providers
RUN /opt/keycloak/bin/kc.sh build

EXPOSE 8080

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
