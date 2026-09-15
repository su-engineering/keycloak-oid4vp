# Development

Use Java 21 and the checked-in Maven wrapper. Docker is required for the demo and E2E tests; Playwright Chromium is required only for browser tests.

## Start here

```sh
./scripts/demo.sh
```

This creates a disposable Keycloak instance with the `su-engineering` theme and synthetic wallet credentials. See [quick start](quickstart.md) for the complete login walkthrough. The demo shares the integration-test infrastructure, generates keys at startup, and does not launch an automated browser.

## Repository map

| Path | Contents |
| --- | --- |
| `src/main/java/io/github/suengineering/keycloak/oid4vp/` | Provider, endpoints, verification, request services, and mappers |
| `src/main/resources/META-INF/` | SPI and bundled-theme registration |
| `src/main/resources/theme/` | `su-engineering` and existing `oid4vp` login themes |
| `src/main/resources/theme-resources/` | Fallback wallet templates and shared completion JavaScript |
| `src/test/java/` | Unit tests, cryptographic fixtures, E2E infrastructure, and local demo |
| `src/test/resources/` | Synthetic realm and credential fixtures |
| `scripts/` | Demo and existing sandbox helpers |
| `deployment/` | Existing Coolify image and Compose configuration |
| `loadtest/` | Clustered browser/SSE load test |
| `docs/` | User, operator, and contributor documentation |

## Running tests

```sh
./mvnw clean test
./mvnw spotless:apply
./mvnw clean verify
```

`test` runs unit and cryptographic tests. `verify` also checks Java formatting, builds the provider, runs Docker/browser E2E tests, and writes coverage to `target/site/jacoco/index.html`. The wallet image is pinned to `v1.8.0` for the test client API.

Install the browser used by the pinned Playwright dependency once:

```sh
./mvnw org.codehaus.mojo:exec-maven-plugin:3.6.3:java -Dexec.mainClass=com.microsoft.playwright.CLI -Dexec.classpathScope=test -Dexec.args='install chromium'
```

On Linux, use `install --with-deps chromium` for required OS packages. CI installs these dependencies automatically.

### Focused checks

```sh
# DID resolution and real SD-JWT cryptography
./mvnw -Dtest=DidWebResolverTest,SdJwtVerifierDidIntegrationTest,DidWebCredentialVerificationTest test

# Both bundled themes, real wallet login, responsive layout, and standard forms
./mvnw verify -Dit.test=KeycloakThemeE2eIT

# Entire suite against the existing Coolify runtime
./mvnw clean verify -Dkeycloak.version=26.5.4
```

The E2E container version follows `keycloak.version`; use `clean` when switching versions. CI runs both 26.5.4 and 26.5.5. Prefer `verify` when selecting E2E classes so the provider is packaged first and Failsafe reports failures correctly.

### What the tests establish

| Layer | Coverage | Boundary |
| --- | --- | --- |
| Unit tests | Configuration, DCQL, request state, mappings, caches, and error handling | Isolated collaborators where appropriate |
| DID cryptographic regression | Real resolver/verifier integration, EC/Ed25519, disclosures, holder binding, negative presentations | HTTPS transport is stubbed; no public DID endpoint |
| Wallet E2E | Running Keycloak, signed/encrypted requests, SD-JWT/mDoc, same/cross-device login, replay/session checks | Synthetic certificate-backed development wallets |
| Theme E2E | Both bundled wallet themes; neutral form validation, modes, local assets, keyboard entry, and 320/390/1440 px overflow checks | Browser regression coverage, not a full accessibility audit |
| OIDF suite | Explicitly selected live conformance scenarios | Requires credentials and external connectivity; excluded by default |

A release must still exercise the deployed did:web credential shape with an authorized HTTPS issuer and a real wallet against the candidate image. Automated coverage is not a substitute for that acceptance test.

### Docker discovery

Docker must be running. If Testcontainers cannot find a nonstandard socket, derive it from the active Docker context:

```sh
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
./mvnw clean verify
```

The socket override is relevant to containerized test helpers. Do not change your global Docker context just to match a copied path from someone else's machine.

### Reports

- `target/surefire-reports/`: unit test results.
- `target/failsafe-reports/`: integration test results.
- `target/site/jacoco/index.html`: combined coverage report.
- CI retains reports for seven days, including failed runs.

There is no `coverage` profile; normal `verify` generates coverage. Test logs can contain synthetic presentations. Review and redact them before sharing.

## Theme development

The demo mounts `src/main/resources/theme/su-engineering/` and disables theme caching. Reload after resource edits. Rebuild/restart for Java or shared extension-resource changes. [Theme documentation](themes.md) covers file responsibilities, screenshot refresh, and compatibility contracts.

## Existing sandbox workflows

These workflows are for integration with an existing sandbox and real wallets. **Both require your own certificate and verifier-info files**, including `--local-wallet`; use `scripts/demo.sh` for a self-contained start.

```sh
scripts/dev.sh --local-wallet
scripts/dev.sh
```

The first starts an installed `oid4vc-dev` CLI and local proxy. The second uses `ngrok` for a public HTTPS hostname. The script's CLI wallet version is whatever is installed on your PATH; it is separate from the pinned Docker wallet used by the demo and tests.

Expected files:

| Default path | Purpose |
| --- | --- |
| `sandbox/sandbox-ngrok-combined.pem` | Verifier signing key and certificate chain |
| `sandbox/sandbox-verifier-info.json` | Verifier attestation payload |

Use `SANDBOX_DIR`, `--pem`, or `--verifier-info` to select another location. Keep these files outside version control.

```sh
scripts/dev.sh --help
```

Common options include `--wallet-port`, `--domain`, `--no-build`, `--skip-realm`, `--no-proxy`, and `--no-ngrok`. Local proxy defaults are Keycloak on `9090`, proxy dashboard on `9091`, and wallet on `8086`. Without the proxy, Keycloak uses `8080`.

For manual realm generation:

```sh
./mvnw package -DskipTests
scripts/setup-local-realm.sh sandbox/sandbox-ngrok-combined.pem sandbox/sandbox-verifier-info.json
docker compose up
```

The generated realm is ignored by Git. The root Compose file mounts that generated file; it cannot start the intended realm from a fresh checkout until generation succeeds.

## Conformance and load testing

Live OIDF conformance requires the explicit `conformance` profile, credentials, and a reachable HTTPS verifier. See [conformance](conformance.md). The clustered browser/SSE workload is documented in [load testing](../loadtest/README.md).
