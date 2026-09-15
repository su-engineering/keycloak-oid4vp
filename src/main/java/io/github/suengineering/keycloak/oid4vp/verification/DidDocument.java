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
package io.github.suengineering.keycloak.oid4vp.verification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * DID Document model for parsing W3C DID Core specification documents.
 *
 * <p>This class represents a DID Document as defined by the W3C DID Core specification.
 * It supports parsing DID documents retrieved from DID resolvers (e.g., did:web) and
 * provides access to verification methods for cryptographic operations.
 *
 * <p>Example DID document structure:
 * <pre>{@code
 * {
 *   "@context": ["https://www.w3.org/ns/did/v1"],
 *   "id": "did:web:example.com",
 *   "verificationMethod": [{
 *     "id": "did:web:example.com#key-1",
 *     "type": "Ed25519VerificationKey2020",
 *     "controller": "did:web:example.com",
 *     "publicKeyJwk": {
 *       "kty": "OKP",
 *       "crv": "Ed25519",
 *       "x": "..."
 *     }
 *   }],
 *   "authentication": ["did:web:example.com#key-1"],
 *   "assertionMethod": ["did:web:example.com#key-1"]
 * }
 * }</pre>
 *
 * @see <a href="https://www.w3.org/TR/did-core/">W3C DID Core Specification</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DidDocument {

    /** DID Document identifier (e.g., "did:web:example.com"). */
    private final String id;

    /** List of verification methods containing public key material. */
    private final List<VerificationMethod> verificationMethod;

    /** List of verification method references or embedded methods for authentication. */
    private final List<Object> authentication;

    /** List of verification method references or embedded methods for assertions. */
    private final List<Object> assertionMethod;

    /**
     * Creates a DID Document with the specified properties.
     *
     * @param id the DID identifier
     * @param verificationMethod the list of verification methods
     * @param authentication the list of authentication references/methods
     * @param assertionMethod the list of assertion method references/methods
     */
    @JsonCreator
    public DidDocument(
            @JsonProperty("id") String id,
            @JsonProperty("verificationMethod") List<VerificationMethod> verificationMethod,
            @JsonProperty("authentication") List<Object> authentication,
            @JsonProperty("assertionMethod") List<Object> assertionMethod) {
        this.id = id;
        this.verificationMethod = verificationMethod != null ? List.copyOf(verificationMethod) : List.of();
        this.authentication = authentication != null ? List.copyOf(authentication) : List.of();
        this.assertionMethod = assertionMethod != null ? List.copyOf(assertionMethod) : List.of();
    }

    /**
     * Parses a DID Document from JSON string.
     *
     * @param json the JSON string representation of a DID document
     * @param mapper the Jackson ObjectMapper to use for parsing
     * @return the parsed DidDocument
     * @throws IllegalArgumentException if parsing fails
     */
    public static DidDocument parse(String json, ObjectMapper mapper) {
        Objects.requireNonNull(json, "JSON string must not be null");
        Objects.requireNonNull(mapper, "ObjectMapper must not be null");
        try {
            return mapper.readValue(json, DidDocument.class);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to parse DID document: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the DID identifier.
     *
     * @return the DID identifier (e.g., "did:web:example.com")
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the list of verification methods.
     *
     * @return an unmodifiable list of verification methods, never null
     */
    public List<VerificationMethod> getVerificationMethod() {
        return verificationMethod;
    }

    /**
     * Returns the list of authentication references or embedded methods.
     *
     * <p>Each element can be either a String (verification method reference) or
     * an embedded VerificationMethod object.
     *
     * @return an unmodifiable list of authentication entries, never null
     */
    public List<Object> getAuthentication() {
        return authentication;
    }

    /**
     * Returns the list of assertion method references or embedded methods.
     *
     * <p>Each element can be either a String (verification method reference) or
     * an embedded VerificationMethod object.
     *
     * @return an unmodifiable list of assertion method entries, never null
     */
    public List<Object> getAssertionMethod() {
        return assertionMethod;
    }

    /**
     * Finds a verification method by its ID.
     *
     * @param methodId the verification method ID to find
     * @return the verification method, or null if not found
     */
    public VerificationMethod findVerificationMethod(String methodId) {
        if (methodId == null) {
            return null;
        }
        return verificationMethod.stream()
                .filter(vm -> methodId.equals(vm.getId()))
                .findFirst()
                .orElse(null);
    }

    /**
     * Finds a verification method by its type.
     *
     * @param type the verification method type (e.g., "Ed25519VerificationKey2020")
     * @return the first matching verification method, or null if not found
     */
    public VerificationMethod findVerificationMethodByType(String type) {
        if (type == null) {
            return null;
        }
        return verificationMethod.stream()
                .filter(vm -> type.equals(vm.getType()))
                .findFirst()
                .orElse(null);
    }

    @Override
    public String toString() {
        return "DidDocument{" + "id='" + id + '\'' + ", verificationMethod=" + verificationMethod.size()
                + " items, authentication=" + authentication.size() + " items, assertionMethod="
                + assertionMethod.size() + " items}";
    }

    /**
     * Represents a verification method in a DID Document.
     *
     * <p>A verification method contains cryptographic material that can be used to
     * verify signatures or perform key agreement operations. The most common type
     * for did:web is Ed25519VerificationKey2020 with a publicKeyJwk.
     *
     * @see <a href="https://www.w3.org/TR/did-core/#verification-methods">W3C DID Core Verification Methods</a>
     */
    public static class VerificationMethod {

        /** Verification method identifier (e.g., "did:web:example.com#key-1"). */
        private final String id;

        /** Verification method type (e.g., "Ed25519VerificationKey2020", "JsonWebKey2020"). */
        private final String type;

        /** Controller DID that owns this verification method. */
        private final String controller;

        /** Public key in JWK format as a map of properties. */
        private final Map<String, Object> publicKeyJwk;

        /** Public key in multibase format (e.g., "z6Mk..." for Ed25519). */
        private final String publicKeyMultibase;

        /**
         * Creates a verification method with the specified properties.
         *
         * @param id the verification method identifier
         * @param type the verification method type
         * @param controller the controller DID
         * @param publicKeyJwk the public key in JWK format
         * @param publicKeyMultibase the public key in multibase format
         */
        @JsonCreator
        public VerificationMethod(
                @JsonProperty("id") String id,
                @JsonProperty("type") String type,
                @JsonProperty("controller") String controller,
                @JsonProperty("publicKeyJwk") Map<String, Object> publicKeyJwk,
                @JsonProperty("publicKeyMultibase") String publicKeyMultibase) {
            this.id = id;
            this.type = type;
            this.controller = controller;
            this.publicKeyJwk = publicKeyJwk != null ? Map.copyOf(publicKeyJwk) : Map.of();
            this.publicKeyMultibase = publicKeyMultibase;
        }

        /**
         * Returns the verification method identifier.
         *
         * @return the verification method ID
         */
        public String getId() {
            return id;
        }

        /**
         * Returns the verification method type.
         *
         * @return the type (e.g., "Ed25519VerificationKey2020")
         */
        public String getType() {
            return type;
        }

        /**
         * Returns the controller DID.
         *
         * @return the controller DID
         */
        public String getController() {
            return controller;
        }

        /**
         * Returns the public key in JWK format.
         *
         * @return an unmodifiable map of JWK properties, never null
         */
        public Map<String, Object> getPublicKeyJwk() {
            return publicKeyJwk;
        }

        /**
         * Returns the public key in multibase format.
         *
         * @return the multibase-encoded public key, or null if not present
         */
        public String getPublicKeyMultibase() {
            return publicKeyMultibase;
        }

        /**
         * Checks if this verification method is of type Ed25519VerificationKey2020.
         *
         * @return true if this is an Ed25519 verification key
         */
        public boolean isEd25519VerificationKey2020() {
            return "Ed25519VerificationKey2020".equals(type);
        }

        /**
         * Checks if this verification method is of type JsonWebKey2020.
         *
         * @return true if this is a JSON Web Key 2020
         */
        public boolean isJsonWebKey2020() {
            return "JsonWebKey2020".equals(type);
        }

        @Override
        public String toString() {
            return "VerificationMethod{" + "id='" + id + '\'' + ", type='" + type + '\'' + ", controller='" + controller
                    + '\'' + '}';
        }
    }
}
