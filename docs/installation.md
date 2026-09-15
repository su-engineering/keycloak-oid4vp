# Installation

Install this extension in a test environment matching your deployment before promotion. It uses Keycloak private SPIs and internal credential APIs, so matching the runtime matters.

## Compatibility

| Component | Baseline |
| --- | --- |
| Java | 21 |
| Maven | Wrapper-pinned 3.9.16 |
| Maven compile target | Keycloak 26.5.5 |
| Root Compose runtime | Keycloak 26.5.5 |
| Existing Coolify runtime | Keycloak 26.5.4 |
| CI runtime matrix | Keycloak 26.5.4 and 26.5.5 |
| Development version | `0.1.0-SNAPSHOT` |

These are tested compatibility targets, not a long-term support promise. Public binary releases are not configured yet; build from a reviewed revision.

## Build the provider

With Java 21, Docker, and the [test browser installed](development.md#running-tests):

```sh
./mvnw clean verify
```

Output: `target/keycloak-extension-oid4vp.jar`. Keep its checksum and source revision with the deployment record. `./mvnw package -DskipTests` produces the same artifact when tests have already passed for that revision.

To compile and test against the existing Coolify runtime instead:

```sh
./mvnw clean verify -Dkeycloak.version=26.5.4
```

## Add it to Keycloak

For a filesystem installation, copy the JAR to `$KC_HOME/providers/`, then run `$KC_HOME/bin/kc.sh build` using your deployment's normal build-time options. Remove any older copy registering the same provider IDs before rebuilding.

A minimal container build for a disposable installation is:

```dockerfile
FROM quay.io/keycloak/keycloak:26.5.5
COPY --chown=keycloak:keycloak target/keycloak-extension-oid4vp.jar /opt/keycloak/providers/keycloak-extension-oid4vp.jar
RUN /opt/keycloak/bin/kc.sh build
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

```sh
docker build -f Dockerfile -t keycloak-oid4vp:local .
```

Save the example as `Dockerfile` in the checkout root before running the command. Supply your database and other Keycloak build-time settings when creating a production image; this snippet only illustrates provider installation. The existing [Coolify image](../deployment/README.md) has its own PostgreSQL and initialization assumptions.

## Configure a realm

1. Open the Admin Console and choose the target realm.
2. Add the **OID4VP** identity provider. Keep alias `oid4vp` if existing applications use `kc_idp_hint=oid4vp`.
3. Define a DCQL query or configure OID4VP claim mappers to derive one. Request only the credential types and claims the application needs.
4. Configure **verifier authentication**: the client ID scheme and its signing material must be accepted by the wallet.
5. Configure **issuer trust**: explicit DID issuers and DID resolution, or the appropriate certificate trust list. Read the [trust reference](configuration.md#trust-and-verification) before enabling fallback paths.
6. Select the stable identifying claim, or enable transient users for a login that should not persist a user. Do not use a display name as an account identifier in a real integration.
7. Add claim mappers and the corresponding Keycloak protocol mappers for claims the application needs in its tokens.
8. Optionally select **Realm settings → Themes → Login theme → su-engineering** and save.

The provider ID is `oid4vp`. Mapper IDs are `oid4vp-user-attribute-mapper` and `oid4vp-user-session-mapper`. These values are independent of the Java package namespace.

## Validate the installation

- Keycloak starts without duplicate-provider, class-loading, or template errors.
- The OID4VP provider appears in the Admin Console.
- A fresh login displays the configured theme and requested wallet flow.
- An approved synthetic credential returns to the initiating browser and produces the expected identity and mapped claims.
- Expired, incorrectly signed, and disallowed-issuer credentials fail as expected for your configuration.
- Same-device and cross-device flows work through your actual proxy and hostname.

Run the did:web path with your authorized test issuer and wallet before upgrading a deployed installation. The certificate-backed E2E suite and DID cryptographic tests cover different parts of the integration.

Next: [configuration](configuration.md), [operations](operations.md), and [migration/rollback](migration.md).
