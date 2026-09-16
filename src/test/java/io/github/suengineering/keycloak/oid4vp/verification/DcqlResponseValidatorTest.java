/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.suengineering.keycloak.oid4vp.domain.PresentationType;
import io.github.suengineering.keycloak.oid4vp.domain.VerifiedCredential;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class DcqlResponseValidatorTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CREDENTIALS = """
            "credentials":[
              {"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":["Identity"]}},
              {"id":"membership","format":"dc+sd-jwt","meta":{"vct_values":["Membership"]}},
              {"id":"license","format":"dc+sd-jwt","meta":{"vct_values":["License"]}}]
            """;

    @Test
    void requiresAllQueriesWhenCredentialSetsAreAbsent() {
        var validator = new DcqlResponseValidator("{" + CREDENTIALS + "}");
        validator.validateSelection(
                Map.of("identity", List.of("vp"), "membership", List.of("vp"), "license", List.of("vp")));
        assertThatThrownBy(() -> validator.validateSelection(Map.of("identity", List.of("vp"))))
                .hasMessageContaining("Missing required");
    }

    @Test
    void supportsAndOrAndOptionalCredentialSets() {
        var validator = new DcqlResponseValidator("{" + CREDENTIALS + """
                ,"credential_sets":[
                  {"options":[["identity"]]},
                  {"options":[["membership"],["license"]],"required":true},
                  {"options":[["membership","license"]],"required":false}]}
                """);
        validator.validateSelection(Map.of("identity", List.of("vp"), "membership", List.of("vp")));
        validator.validateSelection(Map.of("identity", List.of("vp"), "license", List.of("vp")));
        assertThatThrownBy(() ->
                        validator.validateSelection(Map.of("membership", List.of("vp"), "license", List.of("vp"))))
                .hasMessageContaining("Required credential set");
        assertThatThrownBy(() -> validator.validateSelection(Map.of("identity", List.of("vp"))))
                .hasMessageContaining("Required credential set");
    }

    @Test
    void anOptionCanRequireSeveralCredentialsTogether() {
        var validator = new DcqlResponseValidator("{" + CREDENTIALS + """
                ,"credential_sets":[{"options":[["identity","membership"],["license"]]}]}
                """);
        validator.validateSelection(Map.of("identity", List.of("vp"), "membership", List.of("vp")));
        validator.validateSelection(Map.of("license", List.of("vp")));
        assertThatThrownBy(() -> validator.validateSelection(Map.of("identity", List.of("vp"))))
                .hasMessageContaining("Required credential set");
    }

    @Test
    void claimsMustBeSatisfiedWithinEachCredentialRatherThanAcrossCredentials() {
        var validator = validator("""
                "claims":[{"path":["sub"]},{"path":["tier"],"values":["gold"]}]
                """);
        validator.validateCredential(credential(Map.of("sub", "Alice", "tier", "gold")));
        assertThatThrownBy(() -> validator.validateCredential(credential(Map.of("sub", "Alice"))))
                .hasMessageContaining("Required claims or values");
        assertThatThrownBy(() -> validator.validateCredential(credential(Map.of("tier", "gold"))))
                .hasMessageContaining("Required claims or values");
    }

    @ParameterizedTest
    @CsvSource({
        "true,true,true",
        "true,\"true\",false",
        "1,1,true",
        "1,\"1\",false",
        "1,1.0,false",
        "\"gold\",\"gold\",true",
        "\"gold\",\"Gold\",false",
        "true,false,false"
    })
    void expectedValuesMatchExactlyWithoutCoercion(String expected, String actual, boolean accepts) throws Exception {
        var validator = validator("\"claims\":[{\"path\":[\"value\"],\"values\":[" + expected + "]}]");
        VerifiedCredential credential =
                credential(MAPPER.readValue("{\"value\":" + actual + "}", new TypeReference<>() {}));
        if (accepts)
            assertThatCode(() -> validator.validateCredential(credential)).doesNotThrowAnyException();
        else
            assertThatThrownBy(() -> validator.validateCredential(credential))
                    .hasMessageContaining("Required claims or values");
    }

    @Test
    void numericValuesMatchAcrossIntegerRepresentations() {
        var validator = validator("\"claims\":[{\"path\":[\"value\"],\"values\":[1]}]");
        validator.validateCredential(credential(Map.of("value", 1L)));
        validator.validateCredential(credential(Map.of("value", java.math.BigInteger.ONE)));
    }

    @Test
    void claimSetsSupportAlternativeClaimsAndAnEmptyOption() {
        String claims = """
                "claims":[{"id":"member","path":["member"],"values":[true]},
                          {"id":"tier","path":["tier"],"values":["gold"]},
                          {"id":"number","path":["number"]}]
                """;
        var validator = validator(claims + ",\"claim_sets\":[[\"member\"],[\"tier\",\"number\"]]");
        validator.validateCredential(credential(Map.of("member", true)));
        validator.validateCredential(credential(Map.of("tier", "gold", "number", "123")));
        assertThatThrownBy(() -> validator.validateCredential(credential(Map.of("tier", "gold"))))
                .hasMessageContaining("Required claims or values");
        assertThatThrownBy(() -> validator.validateCredential(credential(Map.of("member", false))))
                .hasMessageContaining("Required claims or values");
        validator(claims + ",\"claim_sets\":[[\"member\"],[]]").validateCredential(credential(Map.of()));
    }

    @Test
    void nestedArraysWildcardsAndLiteralKeysAreSupported() throws Exception {
        var claims = MAPPER.<Map<String, Object>>readValue("""
                {"groups":[{"name":"silver"},{"name":"gold"},{"other":true}],"a/b":true,"null":"literal"}
                """, new TypeReference<>() {});
        validator("\"claims\":[{\"path\":[\"groups\",null,\"name\"],\"values\":[\"gold\"]}]")
                .validateCredential(credential(claims));
        validator("\"claims\":[{\"path\":[\"groups\",1,\"name\"],\"values\":[\"gold\"]}]")
                .validateCredential(credential(claims));
        validator("\"claims\":[{\"path\":[\"a/b\"]},{\"path\":[\"null\"],\"values\":[\"literal\"]}]")
                .validateCredential(credential(claims));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"groups\":[]}",
                "{\"groups\":[{}]}",
                "{\"groups\":[{\"name\":\"gold\"},false]}",
                "{\"groups\":{\"name\":\"gold\"}}"
            })
    void invalidPathsAndWildcardTypeErrorsFail(String claims) throws Exception {
        var validator = validator("\"claims\":[{\"path\":[\"groups\",null,\"name\"]}]");
        var credential = credential(MAPPER.readValue(claims, new TypeReference<>() {}));
        assertThatThrownBy(() -> validator.validateCredential(credential))
                .hasMessageContaining("Required claims or values");
    }

    @Test
    void anOutOfRangeIndexCannotWrapAround() {
        var validator = validator("\"claims\":[{\"path\":[\"array\",4294967296]}]");
        assertThatThrownBy(() -> validator.validateCredential(credential(Map.of("array", List.of("gold")))))
                .hasMessageContaining("Required claims or values");
    }

    @Test
    void absentAndExplicitNullAreDifferent() throws Exception {
        var validator = validator("\"claims\":[{\"path\":[\"value\"]}]");
        validator.validateCredential(credential(MAPPER.readValue("{\"value\":null}", new TypeReference<>() {})));
        assertThatThrownBy(() -> validator.validateCredential(credential(Map.of())))
                .hasMessageContaining("Required claims");
    }

    @Test
    void validatesMdocNamespacesTypeAndFormat() {
        var validator = new DcqlResponseValidator("""
                {"credentials":[{"id":"license","format":"mso_mdoc","meta":{"doctype_value":"License"},
                 "claims":[{"path":["org.example.license","category"],"values":["A"]}]}]}
                """);
        var claims = Map.<String, Object>of("org.example.license/category", "A");
        validator.validateCredential(new VerifiedCredential("license", null, "License", claims, PresentationType.MDOC));
        assertThatThrownBy(() -> validator.validateCredential(
                        new VerifiedCredential("license", null, "Wrong", claims, PresentationType.MDOC)))
                .hasMessageContaining("type does not match");
        assertThatThrownBy(() -> validator.validateCredential(
                        new VerifiedCredential("license", "issuer", "License", claims, PresentationType.SD_JWT)))
                .hasMessageContaining("format does not match");
    }

    private static DcqlResponseValidator validator(String conditions) {
        return new DcqlResponseValidator(
                "{\"credentials\":[{\"id\":\"member\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"Membership\"]},"
                        + conditions + "}]}");
    }

    private static VerifiedCredential credential(Map<String, Object> claims) {
        return new VerifiedCredential("member", "issuer", "Membership", claims, PresentationType.SD_JWT);
    }
}
