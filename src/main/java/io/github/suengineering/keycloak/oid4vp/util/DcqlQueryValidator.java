/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashSet;
import java.util.Set;

/** Validates the editable DCQL request structure; does not evaluate presented credentials. */
public final class DcqlQueryValidator {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    private DcqlQueryValidator() {}

    public static void validate(String json) {
        if (json == null || json.isBlank()) {
            return; // An empty editor selects mapper-derived DCQL.
        }
        JsonNode query;
        try {
            query = MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            var location = e.getLocation();
            throw invalid("invalid JSON"
                    + (location == null
                            ? "."
                            : " at line " + location.getLineNr() + ", column " + location.getColumnNr() + "."));
        }
        require(query != null && query.isObject(), "must be a JSON object.");
        JsonNode credentials = query.path("credentials");
        nonEmptyArray(credentials, "credentials");
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < credentials.size(); i++) {
            JsonNode credential = credentials.get(i);
            String path = "credentials[" + i + "]";
            require(credential.isObject(), path + " must be an object.");
            identifier(credential.path("id"), ids, path + ".id");
            String format = credential.path("format").asText();
            require(Set.of("dc+sd-jwt", "mso_mdoc").contains(format), path + ".format must be dc+sd-jwt or mso_mdoc.");
            optionalBoolean(credential, "multiple", path);
            optionalBoolean(credential, "require_cryptographic_holder_binding", path);
            require(
                    credential.path("require_cryptographic_holder_binding").asBoolean(true),
                    path + ".require_cryptographic_holder_binding=false is not supported for wallet login.");
            validateMeta(credential, format, path);
            validateClaims(credential, format, path);
            if (credential.has("trusted_authorities")) {
                JsonNode authorities = credential.get("trusted_authorities");
                nonEmptyArray(authorities, path + ".trusted_authorities");
                for (JsonNode authority : authorities) {
                    require(authority.isObject(), path + ".trusted_authorities entries must be objects.");
                    nonEmptyString(authority.path("type"), path + ".trusted_authorities.type");
                    strings(authority.path("values"), path + ".trusted_authorities.values");
                }
            }
        }
        if (query.has("credential_sets")) {
            JsonNode sets = query.get("credential_sets");
            nonEmptyArray(sets, "credential_sets");
            for (int i = 0; i < sets.size(); i++) {
                String path = "credential_sets[" + i + "]";
                require(sets.get(i).isObject(), path + " must be an object.");
                options(sets.get(i).path("options"), ids, path + ".options", false);
                optionalBoolean(sets.get(i), "required", path);
            }
        }
    }

    private static void validateMeta(JsonNode credential, String format, String path) {
        // Preserve existing support for inferring missing metadata from the credential query ID.
        if (!credential.has("meta")) {
            return;
        }
        JsonNode meta = credential.get("meta");
        require(meta.isObject(), path + ".meta must be an object.");
        if (format.equals("dc+sd-jwt") && meta.has("vct_values")) {
            strings(meta.get("vct_values"), path + ".meta.vct_values");
        }
        if (format.equals("mso_mdoc") && meta.has("doctype_value")) {
            nonEmptyString(meta.get("doctype_value"), path + ".meta.doctype_value");
        }
    }

    private static void validateClaims(JsonNode credential, String format, String path) {
        boolean hasSets = credential.has("claim_sets");
        if (!credential.has("claims")) {
            require(!hasSets, path + ".claim_sets requires claims with IDs.");
            return;
        }
        JsonNode claims = credential.get("claims");
        nonEmptyArray(claims, path + ".claims");
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < claims.size(); i++) {
            JsonNode claim = claims.get(i);
            String claimPath = path + ".claims[" + i + "]";
            require(claim.isObject(), claimPath + " must be an object.");
            if (claim.has("id") || hasSets) {
                identifier(claim.path("id"), ids, claimPath + ".id");
            }
            JsonNode pointer = claim.path("path");
            nonEmptyArray(pointer, claimPath + ".path");
            for (JsonNode part : pointer) {
                require(
                        part.isTextual()
                                || part.isNull()
                                || (part.isIntegralNumber()
                                        && part.bigIntegerValue().signum() >= 0),
                        claimPath + ".path must contain strings, nulls, or non-negative integer indices.");
            }
            if (format.equals("mso_mdoc")) {
                require(
                        pointer.size() == 2
                                && pointer.get(0).isTextual()
                                && pointer.get(1).isTextual(),
                        claimPath + ".path must contain the mDoc namespace and claim name.");
            }
            if (claim.has("values")) {
                JsonNode values = claim.get("values");
                nonEmptyArray(values, claimPath + ".values");
                for (JsonNode value : values) {
                    require(
                            value.isTextual() || value.isBoolean() || value.isIntegralNumber(),
                            claimPath + ".values must contain strings, integers, or booleans.");
                }
            }
        }
        if (hasSets) {
            options(credential.get("claim_sets"), ids, path + ".claim_sets", true);
        }
    }

    private static void options(JsonNode options, Set<String> ids, String path, boolean allowEmptyOption) {
        nonEmptyArray(options, path);
        for (JsonNode option : options) {
            require(
                    option.isArray() && (allowEmptyOption || !option.isEmpty()),
                    path + " must contain " + (allowEmptyOption ? "" : "non-empty ") + "arrays of IDs.");
            for (JsonNode id : option) {
                require(id.isTextual() && ids.contains(id.textValue()), path + " references an unknown ID.");
            }
        }
    }

    private static void identifier(JsonNode id, Set<String> ids, String path) {
        require(
                id.isTextual() && id.textValue().matches("[A-Za-z0-9_-]+"),
                path + " must contain only letters, numbers, underscores, or hyphens.");
        require(ids.add(id.textValue()), path + " must be unique.");
    }

    private static void optionalBoolean(JsonNode node, String key, String path) {
        require(!node.has(key) || node.get(key).isBoolean(), path + "." + key + " must be a boolean.");
    }

    private static void strings(JsonNode node, String path) {
        nonEmptyArray(node, path);
        for (JsonNode item : node) {
            nonEmptyString(item, path);
        }
    }

    private static void nonEmptyString(JsonNode node, String path) {
        require(node.isTextual() && !node.textValue().isBlank(), path + " must contain non-empty strings.");
    }

    private static void nonEmptyArray(JsonNode node, String path) {
        require(node.isArray() && !node.isEmpty(), path + " must be a non-empty array.");
    }

    private static void require(boolean valid, String message) {
        if (!valid) {
            throw invalid(message);
        }
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException("DCQL Query (JSON): " + message);
    }
}
