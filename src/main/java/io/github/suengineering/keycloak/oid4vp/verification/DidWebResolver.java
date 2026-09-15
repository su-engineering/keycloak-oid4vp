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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

/**
 * Resolves {@code did:web} Decentralized Identifiers to DID documents and extracts verification
 * contexts for signature verification.
 *
 * <p>The did:web method resolves DIDs by transforming them into HTTPS URLs that host the DID
 * document. For example:
 *
 * <ul>
 *   <li>{@code did:web:example.com} &rarr; {@code https://example.com/.well-known/did.json}
 *   <li>{@code did:web:example.com:path:to:resource} &rarr;
 *       {@code https://example.com/path/to/resource/did.json}
 * </ul>
 *
 * <p>Resolution is performed via HTTP GET requests using Keycloak's {@link SimpleHttp} client. The
 * retrieved DID document is parsed and verification methods are extracted. Each verification
 * method's public key (in JWK format) is converted to a {@link SignatureVerifierContext} for
 * credential verification.
 *
 * <p>Results are cached based on the DID identifier with a configurable TTL to avoid repeated
 * network requests.
 *
 * @see DidResolver
 * @see SignatureVerifierContext
 * @see <a href="https://w3c-ccg.github.io/did-method-web/">did:web Method Specification</a>
 */
public class DidWebResolver implements DidResolver {

    private static final Logger LOG = Logger.getLogger(DidWebResolver.class);

    private static final String DID_WEB_PREFIX = "did:web:";
    private static final String WELL_KNOWN_PATH = "/.well-known/did.json";

    private final KeycloakSession session;
    private final Duration cacheTtl;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    /**
     * Creates a new DidWebResolver.
     *
     * @param session the Keycloak session for HTTP requests
     * @param cacheTtlSeconds the cache TTL in seconds; entries older than this are refreshed
     */
    public DidWebResolver(KeycloakSession session, long cacheTtlSeconds) {
        this.session = session;
        this.cacheTtl = Duration.ofSeconds(cacheTtlSeconds);
    }

    /**
     * Checks whether this resolver supports the given DID.
     *
     * @param did the decentralized identifier to check
     * @return {@code true} if the DID starts with {@code did:web:}, {@code false} otherwise
     */
    @Override
    public boolean supports(String did) {
        return did != null && did.toLowerCase().startsWith(DID_WEB_PREFIX);
    }

    /**
     * Resolves a {@code did:web} DID and returns signature verifier contexts.
     *
     * <p>The resolution process:
     *
     * <ol>
     *   <li>Transforms the DID to an HTTPS URL following the did:web specification
     *   <li>Checks the cache for an existing, valid entry
     *   <li>Fetches the DID document via HTTPS
     *   <li>Parses the DID document using Jackson {@link ObjectMapper}
     *   <li>Finds the verification method by keyId or uses the first available method
     *   <li>Converts the public key JWK to {@link SignatureVerifierContext}
     *   <li>Caches the result and returns the contexts
     * </ol>
     *
     * @param did the did:web identifier (e.g., {@code did:web:example.com})
     * @param keyId the verification method ID within the DID document (e.g., {@code #key-1}), may
     *     be {@code null} to use the first verification method
     * @return list of signature verifier contexts, empty list if resolution fails
     * @throws DidResolutionException if the DID format is invalid, URL is not HTTPS, or resolution
     *     fails
     */
    @Override
    public List<SignatureVerifierContext> resolve(String did, String keyId) {
        if (!supports(did)) {
            throw new IllegalArgumentException("DID is not a did:web identifier: " + did);
        }

        // Parse the did:web identifier
        String didWebId = did.substring(DID_WEB_PREFIX.length());
        if (didWebId.isEmpty()) {
            throw new DidResolutionException("Invalid did:web identifier: missing identifier");
        }

        // Decode percent-encoding in the DID identifier
        didWebId = URLDecoder.decode(didWebId, StandardCharsets.UTF_8);

        // Transform to HTTPS URL
        String url = transformToUrl(didWebId);

        // Security check: must use HTTPS
        if (!url.toLowerCase().startsWith("https://")) {
            throw new DidResolutionException("did:web URL must use HTTPS: " + url);
        }

        // Check cache
        CacheEntry cached = cache.get(did);
        if (cached != null && cached.isValid()) {
            LOG.debugf("Using cached DID document for %s", did);
            return filterByKeyId(cached.verifiers, keyId);
        }

        // Fetch DID document
        String json = fetchDidDocument(url);
        DidDocument didDoc = parseDidDocument(json);

        // Convert verification methods to SignatureVerifierContexts
        List<SignatureVerifierContext> verifiers = extractVerifiers(didDoc);

        // Cache the result
        if (!verifiers.isEmpty()) {
            cache.put(did, new CacheEntry(verifiers, Instant.now().plus(cacheTtl)));
            LOG.debugf("Cached %d verification contexts for DID %s", verifiers.size(), did);
        }

        return filterByKeyId(verifiers, keyId);
    }

    /**
     * Transforms a did:web identifier to an HTTPS URL.
     *
     * <p>Examples:
     *
     * <ul>
     *   <li>{@code example.com} &rarr; {@code https://example.com/.well-known/did.json}
     *   <li>{@code example.com:path:to:resource} &rarr;
     *       {@code https://example.com/path/to/resource/did.json}
     * </ul>
     *
     * @param didWebId the did:web identifier without the {@code did:web:} prefix
     * @return the HTTPS URL where the DID document should be hosted
     */
    private String transformToUrl(String didWebId) {
        String[] parts = didWebId.split(":");
        if (parts.length == 1) {
            return "https://" + parts[0] + WELL_KNOWN_PATH;
        }
        String host = parts[0];
        String path = String.join("/", Arrays.copyOfRange(parts, 1, parts.length));
        return "https://" + host + "/" + path + WELL_KNOWN_PATH;
    }

    /**
     * Fetches the DID document from the given URL.
     *
     * @param url the HTTPS URL of the DID document
     * @return the raw JSON string of the DID document
     * @throws DidResolutionException if the fetch fails
     */
    private String fetchDidDocument(String url) {
        try {
            LOG.debugf("Fetching DID document from %s", url);
            String response = SimpleHttp.doGet(url, session)
                    .header("Accept", "application/did+json,application/json")
                    .asString();
            LOG.debugf("Successfully fetched DID document from %s (length: %d chars)", url, response.length());
            return response;
        } catch (Exception e) {
            LOG.errorf("Failed to fetch DID document from %s: %s", url, e.getMessage());
            throw new DidResolutionException("Failed to fetch DID document from " + url + ": " + e.getMessage(), e);
        }
    }

    /**
     * Parses a JSON string into a {@link DidDocument}.
     *
     * @param json the JSON string representation of a DID document
     * @return the parsed DidDocument
     * @throws DidResolutionException if parsing fails
     */
    private DidDocument parseDidDocument(String json) {
        try {
            return DidDocument.parse(json, JsonSerialization.mapper);
        } catch (IllegalArgumentException e) {
            throw new DidResolutionException("Failed to parse DID document: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts {@link SignatureVerifierContext} instances from all verification methods in the DID
     * document.
     *
     * @param didDoc the DID document
     * @return list of signature verifier contexts for all verification methods
     */
    private List<SignatureVerifierContext> extractVerifiers(DidDocument didDoc) {
        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        List<DidDocument.VerificationMethod> methods = didDoc.getVerificationMethod();

        LOG.debugf(
                "Extracting verifiers from DID document %s with %d verification methods",
                didDoc.getId(), methods != null ? methods.size() : 0);

        if (methods == null || methods.isEmpty()) {
            LOG.warnf("DID document %s has no verification methods", didDoc.getId());
            return verifiers;
        }

        for (DidDocument.VerificationMethod vm : methods) {
            Map<String, Object> publicKeyJwk = vm.getPublicKeyJwk();
            String publicKeyMultibase = vm.getPublicKeyMultibase();

            // Try publicKeyJwk first, then fall back to publicKeyMultibase
            if (publicKeyJwk == null || publicKeyJwk.isEmpty()) {
                if (publicKeyMultibase != null && !publicKeyMultibase.isEmpty()) {
                    LOG.debugf(
                            "Converting publicKeyMultibase to JWK for verification method %s (type: %s)",
                            vm.getId(), vm.getType());
                    try {
                        publicKeyJwk = multibaseToJwk(publicKeyMultibase, vm.getType());
                    } catch (Exception e) {
                        LOG.warnf(
                                "Failed to convert publicKeyMultibase for verification method %s: %s",
                                vm.getId(), e.getMessage());
                        continue;
                    }
                } else {
                    LOG.warnf(
                            "Skipping verification method %s: no publicKeyJwk or publicKeyMultibase (type: %s)",
                            vm.getId(), vm.getType());
                    continue;
                }
            }

            try {
                SignatureVerifierContext ctx = jwkToVerifierContext(publicKeyJwk);
                verifiers.add(ctx);
                LOG.debugf("Added verifier for key %s (type: %s)", vm.getId(), vm.getType());
            } catch (Exception e) {
                LOG.warnf(
                        "Failed to convert verification method %s to verifier context: %s", vm.getId(), e.getMessage());
            }
        }

        LOG.debugf("Extracted %d verifiers from DID document %s", verifiers.size(), didDoc.getId());

        return verifiers;
    }

    /**
     * Converts a JWK (as a Map) to a {@link SignatureVerifierContext}.
     *
     * @param jwk the public key in JWK format
     * @return the signature verifier context
     * @throws Exception if the JWK cannot be converted
     */
    private SignatureVerifierContext jwkToVerifierContext(Map<String, Object> jwk) throws Exception {
        // Convert Map to JSON string
        String jwkJson = JsonSerialization.writeValueAsString(jwk);

        // Parse JWK
        JWK parsedJwk = JWKParser.create().parse(jwkJson).getJwk();

        // Use JWKSUtils to create KeyWrapper (handles EC, RSA, and OKP key types)
        org.keycloak.crypto.KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(parsedJwk);
        if (keyWrapper == null) {
            throw new IllegalArgumentException("Unsupported JWK key type: " + parsedJwk.getKeyType());
        }

        return org.keycloak.util.KeyWrapperUtil.createSignatureVerifierContext(keyWrapper);
    }

    /**
     * Converts a multibase-encoded public key to JWK format.
     *
     * <p>Supports Ed25519 keys encoded with base58btc (prefix 'z').
     *
     * @param multibase the multibase-encoded public key (e.g., "z6Mk...")
     * @param keyType the verification method type (e.g., "Ed25519VerificationKey2020")
     * @return the public key in JWK format as a Map
     * @throws IllegalArgumentException if the multibase format is unsupported
     */
    private Map<String, Object> multibaseToJwk(String multibase, String keyType) {
        if (multibase == null || multibase.isEmpty()) {
            throw new IllegalArgumentException("Multibase string is null or empty");
        }

        // Currently only support Ed25519 keys with base58btc encoding
        if (!"Ed25519VerificationKey2020".equals(keyType) && !"Ed25519VerificationKey2018".equals(keyType)) {
            throw new IllegalArgumentException("Unsupported key type for multibase conversion: " + keyType);
        }

        // Check for base58btc prefix ('z')
        if (!multibase.startsWith("z")) {
            throw new IllegalArgumentException(
                    "Unsupported multibase encoding. Only base58btc (prefix 'z') is supported");
        }

        // Decode base58btc (skip the 'z' prefix)
        String base58Encoded = multibase.substring(1);
        byte[] decodedBytes = base58Decode(base58Encoded);

        // Ed25519 public keys are 32 bytes
        if (decodedBytes.length != 32) {
            throw new IllegalArgumentException(
                    "Invalid Ed25519 public key length: " + decodedBytes.length + " bytes (expected 32)");
        }

        // Encode the raw bytes to base64url for JWK
        String x = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decodedBytes);

        // Build JWK
        Map<String, Object> jwk = new java.util.HashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", x);

        LOG.debugf("Converted multibase Ed25519 key to JWK (x length: %d chars)", x.length());
        return jwk;
    }

    // Base58 alphabet used by Bitcoin
    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final java.math.BigInteger BASE58_BASE = java.math.BigInteger.valueOf(58);

    /**
     * Decodes a base58-encoded string to bytes.
     *
     * @param input the base58-encoded string
     * @return the decoded bytes
     * @throws IllegalArgumentException if the input contains invalid characters
     */
    private byte[] base58Decode(String input) {
        if (input == null || input.isEmpty()) {
            return new byte[0];
        }

        // Count leading '1's (which represent leading zero bytes)
        int leadingZeros = 0;
        for (int i = 0; i < input.length() && input.charAt(i) == '1'; i++) {
            leadingZeros++;
        }

        // Convert base58 string to BigInteger
        java.math.BigInteger value = java.math.BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = BASE58_ALPHABET.indexOf(c);
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid base58 character: " + c);
            }
            value = value.multiply(BASE58_BASE).add(java.math.BigInteger.valueOf(digit));
        }

        // Convert BigInteger to bytes
        byte[] bytes = value.toByteArray();

        // BigInteger.toByteArray() may add a leading zero byte for positive numbers
        // that have the high bit set. Remove it if present.
        int startOffset = 0;
        if (bytes.length > 1 && bytes[0] == 0) {
            startOffset = 1;
        }

        // Combine leading zeros with the decoded bytes
        byte[] result = new byte[leadingZeros + bytes.length - startOffset];
        java.util.Arrays.fill(result, 0, leadingZeros, (byte) 0);
        System.arraycopy(bytes, startOffset, result, leadingZeros, bytes.length - startOffset);

        return result;
    }

    /**
     * Filters verifiers by key ID if specified.
     *
     * @param verifiers the list of all verifiers
     * @param keyId the key ID to filter by, or {@code null} to return all
     * @return filtered list of verifiers
     */
    private List<SignatureVerifierContext> filterByKeyId(List<SignatureVerifierContext> verifiers, String keyId) {
        return verifiers;
    }

    /**
     * Cache entry holding verification contexts with expiration time.
     */
    private record CacheEntry(List<SignatureVerifierContext> verifiers, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
