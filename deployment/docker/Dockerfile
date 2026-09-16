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

# Stage 2: Runtime - Keycloak with extension
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

# Configure verifier material and credential policy in the Admin Console.
ARG REALM_IMPORT=deployment/realm-import.json
COPY ${REALM_IMPORT} /opt/keycloak/data/import/realm-import.json

# Build optimized Keycloak image with providers
RUN /opt/keycloak/bin/kc.sh build

EXPOSE 8080

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
