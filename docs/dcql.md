# Edit DCQL in the Admin Console

Open **Identity providers → oid4vp → Settings → DCQL Query (JSON)**. Paste the complete JSON object into the multiline editor and save. Use your provider alias if it differs from `oid4vp`.

The query can request your own credential types within the supported SD-JWT VC (`dc+sd-jwt`) and mDoc (`mso_mdoc`) formats. It is independent of login branding. OpenKYC's age credential is one deployment example; the generic realm does not preselect any credential type.

For several credential types, see [DCQL alternatives, multiple providers, and realm isolation](multiple-credential-types.md). A new realm is not required just to configure another credential type.

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
| `credential_sets` | Required or optional combinations of credential query IDs |
| `credentials[].multiple` | Allow several presentations matching this query; defaults to `false` |

Use [the membership example](examples/dcql-membership.json) as a starting point. It requests a membership credential with a `gold` or `platinum` tier and an active membership flag. It requests the subject plus either a member identifier or a contact email. Replace the example credential type and claim names with those your issuer actually supplies.

The strings `"true"` and the boolean `true` have different meanings. `values` is a list of exact matches, not a language for comparisons such as `>=`, regular expressions, or scripts. For the complete syntax, see the [OpenID4VP DCQL specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#dcql_query).

## Save and apply

- Saving validates JSON syntax, supported formats, IDs, claim paths, value types, and references in claim and credential sets. Errors identify the relevant query path; malformed JSON errors include a line and column. An unsuccessful save leaves the previous configuration intact.
- The JSON text is preserved. Unknown extension properties are retained. Existing metadata inference remains available, but explicitly supply your credential type metadata for new configurations.
- An explicit query takes precedence over mapper-derived requests. The **Credential Set Mode** and **Credential Set Purpose** controls apply to mapper-derived DCQL; define those choices in the JSON for a manual query.
- Clear the editor to derive the request from OID4VP mappers. There is no default age credential. A login without either a query or credential mappers fails with a configuration error.
- Start a new login after saving. Claim-to-user and claim-to-token mappings are still configured separately under **Mappers**.

## Request conditions and login policy

The verifier saves the complete normalized DCQL query with each request. It checks the response against that snapshot, so editing the provider while a login is underway does not change that login's DCQL requirements.

Every returned credential must pass signature, lifetime, disclosure/digest, holder-binding and applicable revocation checks. Each response ID must belong to the saved query, and each credential must match that ID's format, type metadata and requested claims. The issuer allow-list applies to **every SD-JWT credential**; mDoc uses certificate trust because it has no canonical `iss` string.

- Without `credential_sets`, every credential query is required.
- With `credential_sets`, every set whose `required` flag is `true` or omitted must have one complete option satisfied. Sets marked `false` may be omitted.
- Without `claim_sets`, all requested claims must be present in each matching credential. With `claim_sets`, one complete claim combination must be satisfied within that credential.
- This provider independently checks `values` on verified claims as its login acceptance policy: exact string, integer or boolean matches, without coercion. A wildcard path succeeds when at least one selected value matches. Missing claims and path type errors fail the affected claim condition.
- Multiple presentations under one query ID require `multiple: true`. Every presentation is verified and retained. Unsupported, malformed or unrequested entries reject the response.

The [OpenID4VP value-matching rules](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.1) describe wallet-side matching as best effort. The checks above run on the server; they do not rely on the wallet applying those hints. Arbitrary comparisons, scripts and unknown extensions are not evaluated. `trusted_authorities` remains a wallet selection hint: configure verifier trust and allowed issuers separately. Per-query SD-JWT issuer restrictions can also use a requested `iss` claim with `values`.

This login provider requires cryptographic holder binding for every credential; `require_cryptographic_holder_binding: false` is rejected at configuration validation. mDoc responses currently require one document per DeviceResponse; put each DeviceResponse in its query's presentation array. A bare legacy token is accepted only for a request with one credential query; multi-query requests require the standard JSON object of presentation arrays.

See [multiple credentials in one login](multiple-credential-types.md#require-several-credentials-in-one-login) for setup, identity selection and mapping.

**Key-Binding Proof Validity Window (seconds)** is a separate timing setting: it limits how old the wallet's signed proof may be. It does not refer to a person's age or select an age credential.
