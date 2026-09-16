/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.suengineering.keycloak.oid4vp.domain.PresentationType;
import io.github.suengineering.keycloak.oid4vp.domain.VerifiedCredential;
import io.github.suengineering.keycloak.oid4vp.util.DcqlQueryValidator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.broker.provider.IdentityBrokerException;

/** Applies the saved request's DCQL constraints to independently verified credentials. */
public final class DcqlResponseValidator {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final JsonNode query;
    private final Map<String, JsonNode> credentials = new LinkedHashMap<>();

    public DcqlResponseValidator(String json) {
        if (json == null || json.isBlank()) {
            throw new IdentityBrokerException("Missing saved DCQL query. Restart the login flow.");
        }
        try {
            DcqlQueryValidator.validate(json);
            query = MAPPER.readTree(json);
            for (JsonNode credential : query.path("credentials")) {
                credentials.put(credential.path("id").textValue(), credential);
            }
        } catch (Exception e) {
            throw new IdentityBrokerException("Invalid saved DCQL query", e);
        }
    }

    public List<String> credentialIds() {
        return List.copyOf(credentials.keySet());
    }

    public void validateSelection(Map<String, ? extends List<?>> presentations) {
        require(!presentations.isEmpty(), "No credentials returned");
        for (var entry : presentations.entrySet()) {
            JsonNode credential = credentials.get(entry.getKey());
            require(credential != null, "Unrequested credential query ID: " + entry.getKey());
            require(!entry.getValue().isEmpty(), "Empty presentation array: " + entry.getKey());
            require(
                    credential.path("multiple").asBoolean(false)
                            || entry.getValue().size() == 1,
                    "Multiple presentations are not allowed for query: " + entry.getKey());
        }
        Set<String> returned = presentations.keySet();
        if (!query.has("credential_sets")) {
            require(returned.containsAll(credentials.keySet()), "Missing required credential query");
        } else {
            for (JsonNode set : query.path("credential_sets")) {
                if (set.path("required").asBoolean(true)) {
                    require(matchesOption(set.path("options"), returned), "Required credential set is not satisfied");
                }
            }
        }
    }

    public void validateCredential(VerifiedCredential credential) {
        String id = credential.credentialId();
        JsonNode requested = credentials.get(id);
        require(requested != null, "Unrequested credential query ID: " + id);
        String format = credential.presentationType() == PresentationType.SD_JWT ? "dc+sd-jwt" : "mso_mdoc";
        require(format.equals(requested.path("format").asText()), "Credential format does not match query: " + id);
        JsonNode meta = requested.path("meta");
        if (credential.presentationType() == PresentationType.SD_JWT && meta.has("vct_values")) {
            boolean matches = false;
            for (JsonNode type : meta.path("vct_values")) {
                if (type.asText().equals(credential.credentialType())) matches = true;
            }
            require(matches, "Credential type does not match query: " + id);
        }
        if (credential.presentationType() == PresentationType.MDOC && meta.has("doctype_value")) {
            require(
                    meta.path("doctype_value").asText().equals(credential.credentialType()),
                    "Credential type does not match query: " + id);
        }
        if (!requested.has("claims")) return;
        JsonNode claims = MAPPER.valueToTree(credential.claims());
        Set<String> satisfied = new HashSet<>();
        boolean all = true;
        for (JsonNode claim : requested.path("claims")) {
            List<JsonNode> values;
            if (credential.presentationType() == PresentationType.MDOC) {
                // mDoc verifier retains namespace/element names as one unambiguous map key.
                String key = claim.path("path").get(0).asText() + "/"
                        + claim.path("path").get(1).asText();
                values = claims.has(key) ? List.of(claims.get(key)) : List.of();
            } else {
                values = resolvePath(claims, claim.path("path"));
            }
            boolean matches = !values.isEmpty();
            if (matches && claim.has("values")) {
                matches = values.stream().anyMatch(value -> matchesValue(value, claim.path("values")));
            }
            all &= matches;
            if (matches && claim.has("id")) satisfied.add(claim.path("id").asText());
        }
        require(
                requested.has("claim_sets") ? matchesOption(requested.path("claim_sets"), satisfied) : all,
                "Required claims or values do not match query: " + id);
    }

    private static boolean matchesOption(JsonNode options, Set<String> satisfied) {
        for (JsonNode option : options) {
            boolean matches = true;
            for (JsonNode id : option) matches &= satisfied.contains(id.asText());
            if (matches) return true;
        }
        return false;
    }

    private static boolean matchesValue(JsonNode actual, JsonNode expectedValues) {
        for (JsonNode expected : expectedValues) {
            if (actual.isIntegralNumber() && expected.isIntegralNumber()) {
                if (actual.bigIntegerValue().equals(expected.bigIntegerValue())) return true;
            } else if (actual.equals(expected)) {
                return true;
            }
        }
        return false;
    }

    private static List<JsonNode> resolvePath(JsonNode claims, JsonNode path) {
        List<JsonNode> selected = List.of(claims);
        for (JsonNode part : path) {
            List<JsonNode> next = new ArrayList<>();
            for (JsonNode current : selected) {
                if ((part.isTextual() && !current.isObject()) || (!part.isTextual() && !current.isArray())) {
                    return List.of(); // A type error in any wildcard branch invalidates this claims path.
                }
                if (part.isTextual() && current.isObject() && current.has(part.textValue())) {
                    next.add(current.get(part.textValue()));
                } else if (part.isNull() && current.isArray()) {
                    current.forEach(next::add);
                } else if (part.isIntegralNumber()
                        && part.canConvertToInt()
                        && current.isArray()
                        && part.intValue() < current.size()) {
                    next.add(current.get(part.intValue()));
                }
            }
            selected = next;
        }
        return selected;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IdentityBrokerException(message);
    }
}
