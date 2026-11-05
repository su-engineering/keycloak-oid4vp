-- Rename the keycloak-oid4vp identity provider ID from "oid4vp" to "oid4vp-wallet".
--
-- Required when upgrading from 0.1.0-rc.1 or earlier. Keycloak 26.8 ships its own
-- experimental OID4VP provider under the ID "oid4vp", so this extension now uses
-- "oid4vp-wallet". Realm aliases, broker URLs, mappers and linked user identities
-- are unchanged.
--
-- Run with Keycloak stopped, against the Keycloak database, after taking a backup:
--   psql "$KC_DB_URL" -v ON_ERROR_STOP=1 -f scripts/migrate-provider-id.sql
--
-- Do not run it if the native Keycloak "oid4vc-vp" feature has been enabled and
-- native OID4VP providers were created: those rows would be renamed too.
--
-- Rollback (with the previous provider JAR):
--   UPDATE identity_provider SET provider_id = 'oid4vp' WHERE provider_id = 'oid4vp-wallet';

BEGIN;

UPDATE identity_provider
SET provider_id = 'oid4vp-wallet'
WHERE provider_id = 'oid4vp';

COMMIT;
