/*
 * Copyright 2026 Bundesagentur für Arbeit
 * Modified by su-engineering: package namespace migration (2026).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.suengineering.keycloak.oid4vp.util;

import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpConstants;
import java.util.List;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Shared configuration property definitions for OID4VP identity provider mappers.
 *
 * <p>Provides reusable Keycloak {@link ProviderConfigProperty} instances for credential format,
 * credential type, claim path, multivalued, and optional flags. Used by both
 * {@link io.github.suengineering.keycloak.oid4vp.mapper.Oid4vpClaimToUserAttributeMapper} and
 * {@link io.github.suengineering.keycloak.oid4vp.mapper.Oid4vpClaimToUserSessionMapper} to present
 * consistent configuration in the Keycloak Admin Console.
 */
public final class Oid4vpMapperConfigProperties {

    public static final String CREDENTIAL_QUERY_ID = "credential.query.id";
    public static final String CREDENTIAL_FORMAT = "credential.format";
    public static final String CREDENTIAL_TYPE = "credential.type";
    public static final String CLAIM_PATH = "claim";
    public static final String MULTIVALUED = "multivalued";
    public static final String OPTIONAL = "optional";

    private Oid4vpMapperConfigProperties() {}

    public static ProviderConfigProperty credentialQueryId() {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(CREDENTIAL_QUERY_ID);
        prop.setLabel("Credential Query ID");
        prop.setHelpText(
                "Optional DCQL query ID to map from, for example membership or license. Format/type filters "
                        + "also apply. Multiple matching presentations require Multi-Valued mapping. Leave all filters "
                        + "blank to use the login identity credential. This field selects responses; it does not rename generated queries.");
        prop.setType(ProviderConfigProperty.STRING_TYPE);
        return prop;
    }

    public static ProviderConfigProperty credentialFormat() {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(CREDENTIAL_FORMAT);
        prop.setLabel("Credential Format");
        prop.setHelpText("Format of the credential containing this claim.");
        prop.setType(ProviderConfigProperty.LIST_TYPE);
        prop.setDefaultValue(Oid4vpConstants.FORMAT_SD_JWT_VC);
        prop.setOptions(List.of(Oid4vpConstants.FORMAT_SD_JWT_VC, Oid4vpConstants.FORMAT_MSO_MDOC));
        return prop;
    }

    public static ProviderConfigProperty credentialType() {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(CREDENTIAL_TYPE);
        prop.setLabel("Credential Type");
        prop.setHelpText("Credential type identifier. For SD-JWT: vct value. For mDoc: docType value.");
        prop.setType(ProviderConfigProperty.STRING_TYPE);
        return prop;
    }

    public static ProviderConfigProperty claimPath() {
        return claimPath(
                "Path to the claim in the credential. Use '/' for nested paths (e.g., 'given_name', 'address/street_address'). "
                        + "For array claims, use 'nationalities' or 'nationalities/null' depending on wallet support "
                        + "(null requests all array elements per DCQL spec).");
    }

    public static ProviderConfigProperty claimPath(String helpText) {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(CLAIM_PATH);
        prop.setLabel("Claim Path");
        prop.setHelpText(helpText);
        prop.setType(ProviderConfigProperty.STRING_TYPE);
        return prop;
    }

    public static ProviderConfigProperty multivalued() {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(MULTIVALUED);
        prop.setLabel("Multi-Valued");
        prop.setHelpText("Enable for array-valued claims (e.g., nationalities). "
                + "Stores all values as a multi-valued custom Keycloak attribute; session-note arrays use JSON.");
        prop.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        prop.setDefaultValue("false");
        return prop;
    }

    public static ProviderConfigProperty optional() {
        ProviderConfigProperty prop = new ProviderConfigProperty();
        prop.setName(OPTIONAL);
        prop.setLabel("Optional Claim");
        prop.setHelpText("If enabled, this claim is optional and triggers claim_set generation in DCQL.");
        prop.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        prop.setDefaultValue("false");
        return prop;
    }

    public static void addCommonProperties(List<ProviderConfigProperty> properties) {
        properties.add(credentialQueryId());
        properties.add(credentialFormat());
        properties.add(credentialType());
        properties.add(claimPath());
        properties.add(multivalued());
        properties.add(optional());
    }
}
