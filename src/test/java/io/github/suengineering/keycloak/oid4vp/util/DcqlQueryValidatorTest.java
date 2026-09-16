/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class DcqlQueryValidatorTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void adminValidationAndNormalizationPreserveCustomCredentialConditions() throws Exception {
        String query = Files.readString(Path.of("docs/examples/dcql-membership.json"));
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setDcqlQuery(query);
        config.validate(null);
        assertThat(config.getDcqlQuery()).isEqualTo(query);
        String normalized = DcqlQueryBuilder.normalizeManualQuery(
                MAPPER, query, Oid4vpTrustedAuthoritiesMode.NONE, null, List.of());
        assertThat(MAPPER.readTree(normalized)).isEqualTo(MAPPER.readTree(query));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\n\t"})
    void blankQueryLeavesMapperModeAvailable(String query) {
        assertThatCode(() -> DcqlQueryValidator.validate(query)).doesNotThrowAnyException();
    }

    @Test
    void validatesMdocAndCredentialAlternativesWithoutRestrictingCredentialTypes() {
        DcqlQueryValidator.validate("""
                {
                  "credentials": [
                    {"id":"membership", "format":"dc+sd-jwt", "meta":{"vct_values":["urn:example:membership"]},
                     "claims":[{"path":["plans",null,"level"],"values":[1,2]}]},
                    {"id":"license", "format":"mso_mdoc", "meta":{"doctype_value":"org.example.license"},
                     "claims":[{"path":["org.example.license","category"],"values":["A","B"]}]}
                  ],
                  "credential_sets":[{"options":[["membership"],["license"]],"required":true}]
                }
                """);
    }

    @Test
    void retainsLegacyMetadataInferenceAndUnknownExtensions() {
        DcqlQueryValidator.validate("""
                {"credentials":[{"id":"membership","format":"dc+sd-jwt",
                 "example_extension":{"value":42}}],"future_extension":true}
                """);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "not-json",
                "{",
                "[]",
                "null",
                "{}",
                "{\"credentials\":[]}",
                "{\"credentials\":[],\"credentials\":[]}",
                "{\"credentials\":[{\"id\":\"x\",\"format\":\"dc+sd-jwt\"}]} {}"
            })
    void rejectsMalformedOrEmptyQueriesAtAdminSave(String query) {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setDcqlQuery(query);
        assertThatThrownBy(() -> config.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("DCQL Query (JSON):");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"id\":\"bad id\",\"format\":\"dc+sd-jwt\"}",
                "{\"id\":\"x\",\"format\":\"unsupported\"}",
                "{\"id\":\"x\",\"format\":\"dc+sd-jwt\",\"meta\":null}",
                "{\"id\":\"x\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[]}}",
                "{\"id\":\"x\",\"format\":\"dc+sd-jwt\",\"multiple\":\"true\"}",
                "{\"id\":\"x\",\"format\":\"dc+sd-jwt\",\"claims\":[]}",
                "{\"id\":\"x\",\"format\":\"dc+sd-jwt\",\"claim_sets\":[[\"missing\"]]}",
                "{\"id\":\"x\",\"format\":\"mso_mdoc\",\"claims\":[{\"path\":[\"missing-namespace\"]}]}"
            })
    void rejectsInvalidCredentialQueryStructure(String credential) {
        assertThatThrownBy(() -> DcqlQueryValidator.validate("{\"credentials\":[" + credential + "]}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("credentials[0]");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"path\":[]}",
                "{\"path\":[-1]}",
                "{\"path\":[true]}",
                "{\"path\":[\"tier\"],\"values\":[]}",
                "{\"path\":[\"tier\"],\"values\":[null]}",
                "{\"path\":[\"tier\"],\"values\":[1.5]}",
                "{\"path\":[\"tier\"],\"values\":[{\"gte\":1}]}"
            })
    void rejectsInvalidPathsAndValueConditions(String claim) {
        String query =
                "{\"credentials\":[{\"id\":\"membership\",\"format\":\"dc+sd-jwt\",\"claims\":[" + claim + "]}]}";
        assertThatThrownBy(() -> DcqlQueryValidator.validate(query))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("credentials[0].claims[0]");
    }

    @Test
    void rejectsAmbiguousIdsAndBrokenSetReferences() {
        String credential = "{\"id\":\"x\",\"format\":\"dc+sd-jwt\"}";
        assertThatThrownBy(
                        () -> DcqlQueryValidator.validate("{\"credentials\":[" + credential + "," + credential + "]}"))
                .hasMessageContaining("unique");
        assertThatThrownBy(() -> DcqlQueryValidator.validate(
                        "{\"credentials\":[" + credential + "],\"credential_sets\":[{\"options\":[[\"unknown\"]]}]}"))
                .hasMessageContaining("unknown ID");
        assertThatThrownBy(() -> DcqlQueryValidator.validate("""
                {"credentials":[{"id":"x","format":"dc+sd-jwt",
                "claims":[{"id":"tier","path":["tier"]}],"claim_sets":[["unknown"]]}]}
                """)).hasMessageContaining("unknown ID");
    }
}
