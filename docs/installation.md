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

One Keycloak server can serve multiple credential policies. A separate realm is optional: use it for isolated users and SSO, or configure multiple OID4VP providers within a shared realm. See [multiple credential types and realms](multiple-credential-types.md).

Use [deployment/realm-import.json](../deployment/realm-import.json) for a new realm. Root Compose and the Coolify Dockerfile import it by default; you can also choose **Create realm → Browse** in the Admin Console and upload that JSON. It creates `wallet`, selects `su-engineering`, generates an ES256 realm key, and binds the `wallet-browser` authentication flow.

The OID4VP provider is initially **disabled**. Configure it before enabling login. The import contains no application clients, users, verifier certificates, issuer policy, or credential query. The separate [local demo](quickstart.md) supplies synthetic credentials for a working example.

Sign into the Admin Console using an administrator from the **master** realm, select **wallet**, and complete setup:

| Setting | Admin Console location | What to configure |
| --- | --- | --- |
| Application | **Clients → Create client** | OIDC client, exact redirect URIs and web origins, PKCE or client authentication as appropriate |
| Appearance | **Realm settings → Themes → Login theme** | `su-engineering` or `openkyc` |
| Wallet entry | **Authentication → Flows → wallet-browser → Identity Provider Redirector → Settings** | Default Identity Provider: `oid4vp` (or your IdP alias) |
| Browser binding | **Authentication → Flows → flow actions → Bind flow → Browser flow** | `wallet-browser` for direct wallet login; `browser` for standard sign-in |
| Wallet links and device flows | **Identity providers → oid4vp → Settings** | Wallet URL Scheme, Enable Same-Device Flow, Enable Cross-Device Flow |
| Requested credentials and conditions | **Identity providers → oid4vp → Settings → DCQL Query (JSON)** | Full JSON query with custom types, paths, expected values and sets; see [DCQL editor guide](dcql.md). Leave blank to derive requests from mappers. |
| Verifier authentication | **Identity providers → oid4vp → Settings** | HAIP, Client ID Scheme, X.509 Certificate (PEM), signing material and optional verifier attestations |
| Issuer trust | **Identity providers → oid4vp → Settings** | Enable DID Resolution and Allowed Issuers (SD-JWT), or the appropriate certificate trust list and its signing certificate |
| Proof timing | **Identity providers → oid4vp → Settings** | Clock Skew (seconds) and Key-Binding Proof Validity Window (seconds); unrelated to the holder's age |
| User identity | **Identity providers → oid4vp → Settings** | Stable User Identifier Claim, or Keycloak's Do not store users option if the transient-users feature is enabled on the server |
| Claims in application tokens | **Identity providers → oid4vp → Mappers**, then the client's dedicated scope / protocol mappers | Requested claims and their destination attributes or session notes |

Request only the credential types and claims the application needs. An explicit **DCQL Query (JSON)** takes precedence over mapper-derived requests; leave it empty when using mappers. Read the [trust reference](configuration.md#trust-and-verification) and configure the trust policy before enabling the provider. Do not use a display name as an account identifier.

After saving the configuration, enable **Identity providers → oid4vp → Enabled**. Start a fresh application authorization request: it opens the wallet screen directly with either theme, without a username/password screen or a provider-selection click. Existing SSO sessions can proceed through the cookie execution. The wallet flow contains no password-form execution; an unavailable provider produces a login failure rather than a password fallback. The master realm's administrator login is unaffected.

For an existing realm, configure its OID4VP provider in the same UI. Copy the built-in `browser` flow and configure its Identity Provider Redirector's default provider to `oid4vp` for automatic wallet entry. For wallet-only access, remove the username/password forms from the copy before binding it. Keycloak documents the redirector in its [default identity provider guide](https://www.keycloak.org/docs/latest/server_admin/#_default_identity_provider).

Startup import only creates absent realms. Editing the JSON and restarting does **not** update an existing realm; use the Admin Console or Admin REST API for subsequent changes. Existing OpenKYC deployments should follow [migration](migration.md#openkyc-theme-rename-and-generic-realm).

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
