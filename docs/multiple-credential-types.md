# Multiple credential types on one Keycloak server

**You do not need a new realm for each credential type.** A realm is useful when you need a separate user directory, SSO session boundary, administration, or token issuer. DCQL and trust configuration belong to each OID4VP identity-provider instance inside a realm.

| Requirement | Configuration |
| --- | --- |
| Accept one of several credential types for the same sign-in | One realm and one OID4VP provider with an explicit DCQL alternative request |
| Offer separate credential requests with shared users and SSO | One realm with multiple OID4VP providers, each with its own alias, DCQL, issuer trust, and mappers |
| Isolate OpenKYC from another application or credential policy | Separate realms on the same Keycloak server; configure clients and providers independently |
| Require different credential types together in one login | One realm and one provider with several DCQL credential queries |

## Separate realms: OpenKYC and membership

For independent deployments on one server, this is the simplest arrangement:

| Realm | Theme | OID4VP query | Application's OIDC issuer |
| --- | --- | --- | --- |
| `openkyc` | `openkyc` | Your OpenKYC credential policy | `https://auth.example/realms/openkyc` |
| `members` | `su-engineering` | Your membership credential policy | `https://auth.example/realms/members` |

1. Install the extension JAR once on the Keycloak server. It is available in every realm.
2. Sign in as a master-realm administrator. Make a copy of [the generic import](../deployment/realm-import.json), change its `realm` value to a unique name, and import it through **Create realm**. Repeat for the other realm, or keep an existing OpenKYC realm.
3. In each realm, configure its application client, redirect URIs, verifier keys, wallet settings, issuer policy, full DCQL query, and claim mappers. Enable the provider after configuration. Follow [realm setup](installation.md#configure-a-realm).
4. Select each realm's login theme and keep its `wallet-browser` flow's redirector pointed at its own provider alias. The same `oid4vp` alias can be used in different realms.
5. Configure each application with its own realm's OIDC issuer, client ID, and client credentials where applicable. The realm is selected by the authorization endpoint URL.

Startup imports skip realms that already exist. Change an existing realm through the Admin Console; restarting with modified import JSON will not update it.

## Multiple providers in one realm

Create two OID4VP identity-provider instances under **Identity providers → Add provider**, using different aliases such as `openkyc-wallet` and `membership-wallet`. Configure each provider's DCQL JSON, allowed issuers/methods, stable user identifier, and mappers separately. Their provider type remains `oid4vp`.

An application can select a provider by adding `kc_idp_hint=membership-wallet` to its normal OIDC authorization request. For default direct wallet entry, configure the **Identity Provider Redirector** in the browser flow with the desired alias. A standard browser flow can instead display a provider-selection screen. See Keycloak's [client-suggested identity provider documentation](https://www.keycloak.org/docs/latest/server_admin/#_client_suggested_idp).

**Provider selection is routing, not an authorization boundary.** The client can change `kc_idp_hint`, and the generic `wallet-browser` flow's Cookie execution can reuse an existing realm SSO session without a new credential presentation. Multiple providers also share the realm's user directory and account-linking behavior. If applications must independently require different credential policies, use separate realms or design and verify explicit server-side authorization and reauthentication rules. A different alias or redirector default alone does not enforce that requirement.

## Alternative types in one provider

Use [the alternative-credential DCQL example](examples/dcql-alternatives.json) when a single login accepts either a membership credential or a professional license. It has two credential queries and a `credential_sets` entry whose options each name one query. Alternatively, `meta.vct_values` can list multiple SD-JWT types when they share the requested claim structure.

The response must satisfy the saved query's required sets and claim conditions. In an alternatives-only request, leave **Identity Credential Query ID** blank to use the first returned query in the request's order, or require a separate identity query and select its ID explicitly.

## Require several credentials in one login

1. Open your realm's **Identity providers → your OID4VP provider → Settings**.
2. Paste [membership and professional license](examples/dcql-membership-and-license.json) into **DCQL Query (JSON)**. Replace the example type URIs and claim paths with your issuer's schema. The example omits `credential_sets`, so **both** credentials are required. They can also use different supported formats, such as an SD-JWT membership plus an mDoc license.
3. Set **Identity Credential Query ID** to `membership`, and **User Identifier Claim (SD-JWT)** to `sub`. The membership identifies the Keycloak user; the license supplies additional verified claims.
4. Configure issuer trust for both credentials, save, and start a new login.
5. Under **Mappers**, add a claim mapper for each value needed by the application. For example:

| Credential Query ID | Credential type | Claim path | User attribute |
| --- | --- | --- | --- |
| `membership` | Your membership VCT | `membership/tier` | `membership_tier` |
| `license` | Your license VCT | `license_number` | `license_number` |

The wallet returns one `vp_token` for the login:

```json
{
  "membership": ["<membership presentation>"],
  "license": ["<license presentation>"]
}
```

To accept **either** credential, add `"credential_sets": [{"options": [["membership"], ["license"]]}]` to the query and clear the explicit identity ID. Both alternatives must then contain a suitable user identifier. To require **identity AND (membership OR license)**, define one required set for the identity query and another with the two alternative options.

### Identity and claim mapping

Claims are stored separately by DCQL query ID. The default identity comes from the first returned query in **request order**, regardless of wallet JSON ordering. An explicit **Identity Credential Query ID** must return exactly one presentation. Persistent credential-based login also rejects multiple presentations for the default identity query. Use a separate single-credential identity query when requesting `multiple: true` for other credentials. Transient users or SIOPv2 subject mode can use the default with multiple presentations because their identity does not come from the credential subject.

A mapper's **Credential Query ID**, **Credential Format**, and **Credential Type** filters all apply. With all filters blank, it reads the identity credential. If several presentations match, enable **Multi-Valued** or narrow the query ID; scalar mappers reject ambiguity. Multi-valued custom user attributes retain all matching values; multi-valued session-note arrays are stored as JSON. Keycloak's scalar profile fields such as email still use the first value, so configure a single credential source for those fields. The query ID mapper field selects responses from the manual JSON; it does not rename IDs in mapper-generated DCQL.

Holder binding proves control of each credential's bound key for this transaction. It does **not** establish that several credentials describe the same person or that different keys belong to the same person. This implementation does not enforce cross-credential subject equality or other relationships. Configure an authoritative identity credential and use additional application policy if those relationships are required.

One realm and one provider are sufficient for these combinations. Separate realms remain useful for independent users, SSO and administration.
