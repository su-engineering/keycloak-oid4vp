# Edit DCQL in the Admin Console

Open **Identity providers → oid4vp → Settings → DCQL Query (JSON)**. Paste the complete JSON object into the multiline editor and save. Use your provider alias if it differs from `oid4vp`.

The query can request your own credential types within the supported SD-JWT VC (`dc+sd-jwt`) and mDoc (`mso_mdoc`) formats. It is independent of login branding. OpenKYC's age credential is one deployment example; the generic realm does not preselect any credential type.

## Define a request

| Part of the query | What to specify |
| --- | --- |
| `credentials[].id` | A unique identifier for this credential query |
| `format` | `dc+sd-jwt` or `mso_mdoc` |
| `meta.vct_values` | SD-JWT credential type identifiers accepted by this request |
| `meta.doctype_value` | mDoc document type |
| `claims[].path` | Claim location; nested JSON paths and array indices are supported in requests |
| `claims[].values` | Expected values with exact types: strings, integers, or booleans |
| `claim_sets` | Alternative combinations of claim IDs within a credential |
| `credential_sets` | Requested combinations of credential query IDs |

Use [the membership example](examples/dcql-membership.json) as a starting point. It requests a membership credential with a `gold` or `platinum` tier and an active membership flag. It requests the subject plus either a member identifier or a contact email. Replace the example credential type and claim names with those your issuer actually supplies.

The strings `"true"` and the boolean `true` have different meanings. `values` is a list of exact matches, not a language for comparisons such as `>=`, regular expressions, or scripts. For the complete syntax, see the [OpenID4VP DCQL specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#dcql_query).

## Save and apply

- Saving validates JSON syntax, supported formats, IDs, claim paths, value types, and references in claim and credential sets. Errors identify the relevant query path; malformed JSON errors include a line and column. An unsuccessful save leaves the previous configuration intact.
- The JSON text is preserved. Unknown extension properties are retained. Existing metadata inference remains available, but explicitly supply your credential type metadata for new configurations.
- An explicit query takes precedence over mapper-derived requests. The **Credential Set Mode** and **Credential Set Purpose** controls apply to mapper-derived DCQL; define those choices in the JSON for a manual query.
- Clear the editor to derive the request from OID4VP mappers. There is no default age credential. A login without either a query or credential mappers fails with a configuration error.
- Start a new login after saving. Claim-to-user and claim-to-token mappings are still configured separately under **Mappers**.

## Request conditions and login policy

The editor configures what the verifier asks the wallet to present. A successful save does not mean all requested conditions are enforced against a returned credential. This baseline checks signatures, proof binding, requested credential types, and its configured issuer/status policies, but does not fully evaluate DCQL claim paths, `values`, or claim/credential-set satisfaction on responses. It also rejects responses containing mixed credential types and retains only the primary credential from same-type responses.

Use an explicit server-side acceptance policy for access decisions based on returned claims. The [OpenID4VP value-matching rules](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.1) also distinguish wallet selection hints from verifier security checks. The JSON editor and query validation do not add a condition-enforcement engine.

**Key-Binding Proof Validity Window (seconds)** is a separate timing setting: it limits how old the wallet's signed proof may be. It does not refer to a person's age or select an age credential.
