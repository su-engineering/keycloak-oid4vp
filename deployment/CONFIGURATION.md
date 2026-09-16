# Realm configuration

New deployments use [realm-import.json](realm-import.json), which creates a generic `wallet` realm with the `su-engineering` theme and direct wallet login. Configure clients, credential requests, trust, and verifier material in Keycloak's Admin Console, then enable the OID4VP provider.

Follow the [Admin Console setup guide](../docs/installation.md#configure-a-realm) for the exact locations of each setting. Subsequent changes belong in the Admin Console or Admin REST API: restarting with an edited import does not update an existing realm.

## OpenKYC deployments

The previous realm is retained at [examples/realm-openkyc.json](examples/realm-openkyc.json). It preserves the `openkyc-partners` realm, age-over-18 credential request, clients, and `oid4vp-browser` flow, and now selects the `openkyc` theme.

Set `OID4VP_REALM_IMPORT=deployment/examples/realm-openkyc.json` in Coolify before rebuilding. For an already imported realm, change its login theme to `openkyc` in **Realm settings → Themes**. Leave the provider alias `oid4vp` unchanged. Review the [migration instructions](../docs/migration.md#openkyc-theme-rename-and-generic-realm) before upgrading.

See [deployment instructions](README.md) for database, hostname, and image settings.
