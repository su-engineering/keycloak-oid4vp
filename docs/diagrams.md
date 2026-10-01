# Architecture and protocol diagrams

The extension runs inside Keycloak as an identity provider. It adds wallet verification to the broker flow; applications continue to authenticate through Keycloak. These diagrams describe this implementation, including optional trust paths. They are not conformance claims.

## Components and trust boundaries

```mermaid
flowchart TB
    Browser[Browser] -->|Starts login| KC
    App[Application] <-->|OIDC| KC
    Wallet[Credential wallet] -->|OID4VP presentation| VP
    subgraph KC[Keycloak deployment]
        Theme[Login theme] --> Request[Request object service]
        Request --> State[Shared single-use object store]
        VP[Presentation verifier] --> Mapping[Identity and claim mapping]
        Mapping --> Broker[Keycloak broker completion]
        State --> Broker
        State --> StatusCheck[Cross-device status check]
        StatusCheck --> Theme
    end
    Request -->|Signed request| Wallet
    VP -->|HTTPS keys, when DID enabled| DID[did:web document]
    VP -->|X.509 trust anchors| Trust[ETSI trust list]
    VP -->|Non-HAIP fallback| Metadata[Issuer metadata / JWKS]
    VP -->|Credential status| Status[Status list]
```

**Trust sources are policy inputs.** A valid signature proves control of a key; issuer authorization depends on configuration and the checks actually implemented. Read [DID limitations](configuration.md#didweb-issuer-verification) and [trust-list signature policy](configuration.md#trust-and-verification).

In a cluster, any node can answer the login page's status polls because each poll reads shared completion state. The authentication session and single-use object store must be available across nodes.

## Login and completion

```mermaid
sequenceDiagram
    autonumber
    actor Person
    participant Browser
    participant Wallet
    participant KC as Keycloak verifier
    participant Trust as Configured trust sources

    Person->>Browser: Start wallet sign-in
    Browser->>KC: OIDC login / identity provider
    KC-->>Browser: Wallet link and QR code
    opt Cross-device
        loop Every poll interval until complete
            Browser->>KC: GET /cross-device/status
            KC-->>Browser: pending
        end
    end
    Person->>Wallet: Open link or scan QR
    Wallet->>KC: Fetch request object
    KC-->>Wallet: Signed DCQL request with nonce and state
    Wallet-->>Person: Show requested credentials and claims
    Person->>Wallet: Review and approve
    Wallet->>KC: POST presentation response
    KC->>Trust: Resolve keys and check configured trust/status
    KC->>KC: Verify signature, disclosure, holder/device binding
    KC->>KC: Store deferred identity; invalidate flow handle
    alt Same-device
        KC-->>Wallet: Return completion URL
        Wallet->>Browser: Open completion URL
    else Cross-device
        KC-->>Wallet: Acknowledge response
        Browser->>KC: GET /cross-device/status
        KC-->>Browser: complete, with completion URL
    end
    Browser->>KC: Complete in the initiating browser session
    KC->>KC: Consume deferred state and run broker flow
    KC-->>Browser: Continue application login
```

The wallet presentation and the browser login are separate requests. The final browser step must match the authentication session that initiated the flow.

## SD-JWT issuer key resolution

```mermaid
flowchart TD
    Start[SD-JWT credential] --> Enabled{DID resolution enabled<br/>and supported issuer DID?}
    Enabled -->|Yes| DID[Resolve did:web keys]
    DID -->|Keys returned| Verify[Verify signature, disclosures<br/>and holder binding]
    DID -->|No usable keys / resolution failure| X509[Try x5c certificate chain]
    Enabled -->|No| X509
    X509 -->|Trusted chain| Verify
    X509 -->|No trusted chain| Strict{Strict X.509 mode?}
    Strict -->|Yes| Reject[Reject]
    Strict -->|No| Metadata[Try issuer metadata / JWKS]
    Metadata -->|Key found| Verify
    Metadata -->|No usable key| Direct[Try direct trusted certificates]
    Direct -->|Key found| Verify
    Direct -->|No trusted key| Reject
    Verify -->|Invalid presentation| Reject
    Verify -->|Valid presentation| Policy[Credential type, issuer policy<br/>and status processing]
```

DID resolution precedes strict X.509 handling in this baseline. A failed signature under resolved DID keys does not mean “trust the presentation anyway.” See the [code walkthrough](request-flow.md) for the surrounding callback and policy checks, and [configuration](configuration.md) for defaults.

## State lifecycle

| Value | Created | Used for | Invalidated / consumed |
| --- | --- | --- | --- |
| `request_handle` | Once for each enabled device flow when the login page is rendered | Request lookup, browser binding, completion subscription | Successful callback invalidates the flow handle; completion has separate deferred state |
| `state` and `nonce` | Each request-object fetch | Bind the presentation to a particular request instance | Expiry or invalidation of the parent flow |
| Response encryption key | Per encrypted request instance | Decrypt the corresponding `direct_post.jwt` response | Request-context lifetime |
| Deferred identity | After accepted presentation | Resume the broker flow in the original browser | `/complete-auth` consumption or expiry |
| Completion marker | Accepted cross-device response | Let status polls observe completion | Completion consumption or TTL |

Source-level responsibilities and the precise stored keys are documented in [request flow](request-flow.md).
