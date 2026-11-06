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
import java.util.Arrays;
import java.util.LinkedHashMap;
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
 *   <li>{@code did:web:example.com%3A8443} &rarr; {@code https://example.com:8443/.well-known/did.json}
 * </ul>
 *
 * <p>Only keys referenced by the document's {@code assertionMethod} are eligible to sign
 * credentials. The document {@code id} must equal the DID, a method's {@code controller} (when
 * present) must be the DID, and a JOSE {@code kid} must name one of the eligible methods.
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
    /** Largest DID document accepted over HTTP. */
    static final long MAX_DID_DOCUMENT_BYTES = 256 * 1024;

    private final KeycloakSession session;
    private final Duration cacheTtl;
    private final boolean legacyPathLayout;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    /**
     * Creates a new DidWebResolver.
     *
     * @param session the Keycloak session for HTTP requests
     * @param cacheTtlSeconds the cache TTL in seconds; entries older than this are refreshed
     */
    public DidWebResolver(KeycloakSession session, long cacheTtlSeconds) {
        this(session, cacheTtlSeconds, false);
    }

    /**
     * Creates a new DidWebResolver.
     *
     * @param legacyPathLayout resolve path DIDs from {@code /<path>/.well-known/did.json} and
     *     percent-decode before splitting, as releases up to 0.1.0-rc.1 did, instead of the
     *     standard {@code /<path>/did.json} layout
     */
    public DidWebResolver(KeycloakSession session, long cacheTtlSeconds, boolean legacyPathLayout) {
        this.session = session;
        this.cacheTtl = Duration.ofSeconds(cacheTtlSeconds);
        this.legacyPathLayout = legacyPathLayout;
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
            return selectByKeyId(cached.assertionKeys, did, keyId);
        }

        // Fetch DID document
        String json = fetchDidDocument(url);
        DidDocument didDoc = parseDidDocument(json);
        if (!did.equals(didDoc.getId())) {
            throw new DidResolutionException("DID document id " + didDoc.getId() + " does not match " + did);
        }

        // Only assertionMethod keys may sign credentials
        Map<String, SignatureVerifierContext> assertionKeys = extractAssertionKeys(didDoc, did);

        // Cache the result
        if (!assertionKeys.isEmpty()) {
            cache.put(did, new CacheEntry(assertionKeys, Instant.now().plus(cacheTtl)));
            LOG.debugf("Cached %d assertion keys for DID %s", assertionKeys.size(), did);
        }

        return selectByKeyId(assertionKeys, did, keyId);
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
    String transformToUrl(String didWebId) {
        if (legacyPathLayout) {
            // Earlier releases decoded before splitting. Keep that layout, but never let decoded
            // characters choose another host, user info, query or fragment.
            String[] parts = URLDecoder.decode(didWebId, StandardCharsets.UTF_8).split(":");
            if (!parts[0].matches("[A-Za-z0-9.-]+")) {
                throw new DidResolutionException("Invalid did:web host: " + parts[0]);
            }
            for (int i = 1; i < parts.length; i++) {
                if (!isSafeSegment(parts[i])) {
                    throw new DidResolutionException("Invalid did:web path segment: " + parts[i]);
                }
            }
            if (parts.length == 1) {
                return "https://" + parts[0] + WELL_KNOWN_PATH;
            }
            String path = String.join("/", Arrays.copyOfRange(parts, 1, parts.length));
            return "https://" + parts[0] + "/" + path + WELL_KNOWN_PATH;
        }

        // did:web spec: split on ':' first, then percent-decode each part, so an encoded port
        // (%3A) stays part of the host.
        String[] parts = didWebId.split(":", -1);
        String host = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
        if (!host.matches("[A-Za-z0-9.-]+(:[0-9]{1,5})?")) {
            throw new DidResolutionException("Invalid did:web host: " + host);
        }
        if (parts.length == 1) {
            return "https://" + host + WELL_KNOWN_PATH;
        }
        StringBuilder path = new StringBuilder();
        for (int i = 1; i < parts.length; i++) {
            String segment = URLDecoder.decode(parts[i], StandardCharsets.UTF_8);
            if (!isSafeSegment(segment)) {
                throw new DidResolutionException("Invalid did:web path segment: " + segment);
            }
            path.append('/').append(parts[i]);
        }
        return "https://" + host + path + "/did.json";
    }

    private static boolean isSafeSegment(String segment) {
        return !segment.isEmpty()
                && !segment.equals(".")
                && !segment.equals("..")
                && !segment.contains("/")
                && !segment.contains("\\")
                && !segment.contains("?")
                && !segment.contains("#")
                && !segment.contains("@");
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
            io.github.suengineering.keycloak.oid4vp.util.OutboundUrlPolicy.check(session, url);
            String response = SimpleHttp.doGet(url, session)
                    .header("Accept", "application/did+json,application/json")
                    .setMaxConsumedResponseSize(MAX_DID_DOCUMENT_BYTES)
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
     * Returns the verifier contexts of the document's {@code assertionMethod} keys, keyed by their
     * absolute verification method ID. References may be relative ({@code #key-1}) or absolute;
     * embedded methods are supported. Methods controlled by another DID are skipped.
     */
    @SuppressWarnings("unchecked")
    Map<String, SignatureVerifierContext> extractAssertionKeys(DidDocument didDoc, String did) {
        Map<String, SignatureVerifierContext> keys = new LinkedHashMap<>();
        for (Object entry : didDoc.getAssertionMethod()) {
            DidDocument.VerificationMethod vm;
            if (entry instanceof String reference) {
                String absolute = absoluteMethodId(did, reference);
                vm = didDoc.getVerificationMethod().stream()
                        .filter(candidate -> absolute.equals(absoluteMethodId(did, candidate.getId())))
                        .findFirst()
                        .orElse(null);
                if (vm == null) {
                    LOG.warnf("assertionMethod %s of %s has no matching verification method", reference, did);
                    continue;
                }
            } else if (entry instanceof Map<?, ?> embedded) {
                vm = JsonSerialization.mapper.convertValue(embedded, DidDocument.VerificationMethod.class);
            } else if (entry instanceof DidDocument.VerificationMethod embeddedMethod) {
                vm = embeddedMethod;
            } else {
                continue;
            }

            if (vm.getId() == null) {
                continue;
            }
            if (vm.getController() != null && !did.equals(vm.getController())) {
                LOG.warnf("Skipping %s: controlled by %s, not %s", vm.getId(), vm.getController(), did);
                continue;
            }
            SignatureVerifierContext ctx = toVerifierContext(vm);
            if (ctx != null) {
                keys.put(absoluteMethodId(did, vm.getId()), ctx);
            }
        }
        if (keys.isEmpty()) {
            LOG.warnf("DID document %s has no usable assertionMethod keys", did);
        }
        return keys;
    }

    private SignatureVerifierContext toVerifierContext(DidDocument.VerificationMethod vm) {
        Map<String, Object> publicKeyJwk = vm.getPublicKeyJwk();
        String publicKeyMultibase = vm.getPublicKeyMultibase();
        try {
            if (publicKeyJwk == null || publicKeyJwk.isEmpty()) {
                if (publicKeyMultibase == null || publicKeyMultibase.isEmpty()) {
                    LOG.warnf("Skipping verification method %s: no public key", vm.getId());
                    return null;
                }
                publicKeyJwk = multibaseToJwk(publicKeyMultibase, vm.getType());
            }
            return jwkToVerifierContext(publicKeyJwk);
        } catch (Exception e) {
            LOG.warnf("Failed to convert verification method %s: %s", vm.getId(), e.getMessage());
            return null;
        }
    }

    static String absoluteMethodId(String did, String methodId) {
        if (methodId == null) return null;
        if (methodId.startsWith("#")) return did + methodId;
        if (methodId.startsWith("did:")) return methodId;
        return did + "#" + methodId;
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
    /**
     * Returns the keys a credential may be verified with: all assertion keys without a {@code kid},
     * otherwise only the key the {@code kid} names. An unknown {@code kid} rejects resolution.
     */
    private List<SignatureVerifierContext> selectByKeyId(
            Map<String, SignatureVerifierContext> assertionKeys, String did, String keyId) {
        if (keyId == null || keyId.isBlank()) {
            return List.copyOf(assertionKeys.values());
        }
        SignatureVerifierContext key = assertionKeys.get(absoluteMethodId(did, keyId));
        if (key == null) {
            throw new DidResolutionException("kid " + keyId + " is not an assertionMethod key of " + did);
        }
        return List.of(key);
    }

    /**
     * Cache entry holding verification contexts with expiration time.
     */
    private record CacheEntry(Map<String, SignatureVerifierContext> assertionKeys, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
