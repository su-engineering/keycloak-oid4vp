# Keycloak OID4VP Extension

Wallet-based login for Keycloak, maintained by [su-engineering](https://github.com/su-engineering). Verify SD-JWT credentials issued by **did:web** issuers as well as credentials backed by **X.509 certificates**.

The extension creates OID4VP requests, verifies wallet responses, maps disclosed claims, and completes the Keycloak login flow. It supports same-device links, cross-device QR codes, SD-JWT VC, mDoc, DCQL, `direct_post`, and `direct_post.jwt`.

This is the independent development baseline. The did:web SD-JWT flow is deployed; broader enterprise support and public releases are being prepared. See the [readiness plan](docs/enterprise-readiness.md).

## Build and test

Use **Java 21**. The Maven wrapper downloads pinned Maven **3.9.16** on its first run.

```sh
./mvnw clean test                  # Unit and cryptographic regression tests
./mvnw clean verify                # Formatting, unit tests, Docker/browser E2E tests, coverage
./mvnw package -DskipTests         # Build a provider JAR after testing
```

Docker is required for E2E tests. See [development](docs/development.md) for browser installation and Docker setup.

The compile target and root Compose image are Keycloak **26.5.5**. The existing Coolify Dockerfile remains pinned to **26.5.4**. A runtime upgrade is a separate migration; changing Maven dependencies alone does not upgrade the deployed server.

## Install

Copy `target/keycloak-extension-oid4vp.jar` into Keycloak's `providers/` directory and rebuild the Keycloak image. Install one copy of the extension. The provider ID and bundled login theme are both named `oid4vp`.

See [deployment/README.md](deployment/README.md) for the existing container deployment.

## did:web credentials

Enable DID resolution in the OID4VP identity provider configuration:

```json
{
  "didResolutionEnabled": "true",
  "allowedDidMethods": "did:web",
  "didCacheTtlSeconds": "3600",
  "allowedIssuers": "did:web:issuer.example",
  "enforceHaip": "false"
}
```

This is a config fragment, not a complete realm import. Configure the requested credential type, verifier signing material, and claim mappings as described in [configuration](docs/configuration.md).

For a DID issuer, the verifier fetches the issuer's DID document over HTTPS and uses its public keys to verify the credential. It then verifies holder binding and disclosures. Existing X.509 and issuer-metadata paths remain available. DID issuer verification is separate from the certificate used to identify the verifier to the wallet.

Read the [did:web compatibility notes](docs/configuration.md#didweb-issuer-verification) before changing issuer formats or trust policy.

## Documentation

- [Configuration](docs/configuration.md)
- [Development and testing](docs/development.md)
- [Migration and rollback](docs/migration.md)
- [Enterprise readiness](docs/enterprise-readiness.md)
- [Request flow](docs/request-flow.md) and [diagrams](docs/diagrams.md)
- [OIDF conformance testing](docs/conformance.md)
- [Load testing](loadtest/README.md)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for retained third-party attribution.
