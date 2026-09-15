# Development

## Prerequisites

- Java 21
- Maven 3.9.16 via the checked-in `./mvnw` wrapper
- Docker
- [`oid4vc-dev`](https://github.com/dominikschlosser/oid4vc-dev) for local wallet-based development
- `ngrok` for public HTTPS testing with real wallets

## Quick Start

### Local Wallet Mode

```bash
scripts/dev.sh --local-wallet
```

This mode:

- builds the extension
- generates a local realm config
- starts an `oid4vc-dev` wallet with sample PID credentials
- starts the `oid4vc-dev` debugging proxy
- launches Keycloak behind that proxy

Typical access points:

- Keycloak: `http://localhost:9090`
- Admin Console: `http://localhost:9090/admin`
- Account Console: `http://localhost:9090/realms/wallet-demo/account`
- `oid4vc-dev` dashboard: `http://localhost:9091`
- wallet UI: `http://localhost:8086`

### Sandbox Mode

```bash
scripts/dev.sh
```

This mode builds the extension, generates a realm config from sandbox certificate material, starts `ngrok`, and runs Keycloak with a public HTTPS base URL suitable for real cross-device wallet tests.

Expected sandbox inputs:

| File | Description |
|------|-------------|
| `sandbox-ngrok-combined.pem` | Verifier certificate material used for request-object signing and `x5c` headers |
| `sandbox-verifier-info.json` | Verifier attestation payload for the `verifier_info` claim |

Override the defaults with `--pem`, `--verifier-info`, or `SANDBOX_DIR`.

## Script Options

```text
--local-wallet           Use local oid4vc-dev wallet
--wallet-port <port>     oid4vc-dev wallet port (default: 8086)
--pem <file>             Custom PEM file
--verifier-info <file>   Custom verifier info JSON
--domain <name>          Override ngrok domain
--no-build               Skip Maven build
--skip-realm             Skip realm config generation
--no-proxy               Disable oid4vc-dev proxy
--no-ngrok               Run Keycloak without ngrok
--ngrok-only             Start only the ngrok tunnel
```

## Manual Setup

```bash
./mvnw package -DskipTests
scripts/setup-local-realm.sh sandbox/sandbox-ngrok-combined.pem sandbox/sandbox-verifier-info.json
```

Then either:

- run `docker compose up` for localhost-only testing, or
- run `scripts/run-keycloak-ngrok.sh --domain <your-ngrok-domain>` for public HTTPS testing.

## Running Tests

```sh
./mvnw clean test
./mvnw spotless:apply
./mvnw clean verify
```

`test` runs unit and cryptographic tests. `verify` also checks formatting, builds the provider, runs the Docker/browser E2E suite, and writes coverage to `target/site/jacoco/index.html`. The E2E wallet image is pinned to `v1.8.0` to match the test client API.

Install the browser used by the pinned Playwright dependency once:

```sh
./mvnw org.codehaus.mojo:exec-maven-plugin:3.6.3:java -Dexec.mainClass=com.microsoft.playwright.CLI -Dexec.classpathScope=test -Dexec.args='install chromium'
```

On Linux, use `install --with-deps chromium` for required OS packages. Docker must be running. If Testcontainers cannot find a nonstandard Docker socket (for example OrbStack), configure it from the active Docker context:

```sh
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
./mvnw clean verify
```

For did:web iteration:

```sh
./mvnw -Dtest=DidWebResolverTest,SdJwtVerifierDidIntegrationTest,DidWebCredentialVerificationTest test
```

The combined credential test uses the real resolver and cryptographic verifier with synthetic EC/Ed25519 credentials; only HTTPS transport is stubbed. It covers disclosure and holder binding, old-but-unexpired issuance, and rejection of bad signatures, expired credentials, incorrect nonce/audience, and tampered disclosures. It does not replace a release-image test with a real wallet and HTTPS issuer.

To verify the other existing deployment version:

```sh
./mvnw clean verify -Dkeycloak.version=26.5.4
```

The test container version follows the Maven property. CI checks both 26.5.4 and 26.5.5. Run `clean` when switching versions. When selecting individual E2E classes, use `./mvnw verify -Dit.test=KeycloakOid4vpLoginE2eIT` so the provider is built and Failsafe checks the result.

Live OIDF conformance is excluded by default and enabled with `-Pconformance`; it also needs credentials. There is no `coverage` profile: normal `verify` generates coverage.

## Conformance

For OIDF verifier conformance setup and execution, see [conformance.md](conformance.md).

## Load Testing

For clustered browser+SSE load testing of the cross-device flow, see [../loadtest/README.md](../loadtest/README.md).
