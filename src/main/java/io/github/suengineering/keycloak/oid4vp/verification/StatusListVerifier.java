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

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;

/**
 * Verifies credential revocation status using Token Status List (draft-ietf-oauth-status-list).
 *
 * <p>Credentials may contain a {@code status.status_list} claim with {@code uri} and {@code idx}.
 * The URI points to a JWT whose payload contains a DEFLATE-compressed bitstring.
 * A non-zero value at the credential's index means the credential is revoked.
 */
public class StatusListVerifier {

    private static final Logger LOG = Logger.getLogger(StatusListVerifier.class);
    private static final int DEFAULT_BITS_PER_STATUS = 1;
    /** Largest Status List Token accepted over HTTP. */
    static final long MAX_STATUS_LIST_TOKEN_BYTES = 4L * 1024 * 1024;
    /** Largest decompressed status list accepted (128 Mi one-bit entries). */
    static final int MAX_DECOMPRESSED_STATUS_LIST_BYTES = 16 * 1024 * 1024;

    private static final String TRUST_ANCHOR_DOMAIN = "trust-anchors";
    private static final ConcurrentHashMap<String, CachedStatusList> CACHE = new ConcurrentHashMap<>();

    /**
     * How the signature of a Status List Token may be trusted for one referenced credential.
     *
     * <p>Trust-list certificates (revocation services, otherwise issuance services) are always
     * tried first. When the referenced credential was verified with issuer keys that are not
     * certificate-based, such as a did:web issuer, the Status List Token may instead be signed by
     * one of those same keys.
     *
     * @param issuer the referenced credential's issuer, used to scope cached lists
     * @param issuerVerifiers the keys that verified the referenced credential
     */
    public record StatusListTrust(String issuer, List<SignatureVerifierContext> issuerVerifiers) {
        public StatusListTrust {
            issuerVerifiers = issuerVerifiers != null ? List.copyOf(issuerVerifiers) : List.of();
        }

        public static StatusListTrust trustAnchorsOnly() {
            return new StatusListTrust(null, List.of());
        }
    }

    private final KeycloakSession session;
    private final TrustListProvider trustListProvider;
    private final Duration maxCacheTtl;

    /** Test-only constructor that creates a verifier without session or trust provider. */
    StatusListVerifier() {
        this(null, null);
    }

    public StatusListVerifier(KeycloakSession session, TrustListProvider trustListProvider) {
        this(session, trustListProvider, null);
    }

    public StatusListVerifier(KeycloakSession session, TrustListProvider trustListProvider, Duration maxCacheTtl) {
        this.session = session;
        this.trustListProvider = trustListProvider;
        this.maxCacheTtl = maxCacheTtl;
    }

    /**
     * Checks the revocation status of a credential based on its payload claims.
     * If no status claim is present, this method returns silently.
     *
     * @throws IllegalStateException if the credential is revoked or status check fails
     */
    public void checkRevocationStatus(Map<String, Object> claims) {
        checkRevocationStatus(claims, StatusListTrust.trustAnchorsOnly());
    }

    /**
     * Checks the revocation status of a credential, accepting a Status List Token signed either by
     * the trust anchors or by one of the given issuer keys.
     *
     * @throws IllegalStateException if the credential is revoked or status check fails
     */
    public void checkRevocationStatus(Map<String, Object> claims, StatusListTrust trust) {
        StatusReference ref = extractStatusReference(claims);
        if (ref == null) {
            LOG.debug("No status_list claim found in credential — skipping revocation check");
            return;
        }

        LOG.infof("Checking revocation status: uri=%s, idx=%d", ref.uri, ref.idx);

        try {
            DecodedStatusList statusList = fetchAndDecodeStatusList(ref.uri, trust);
            int status = getStatusAtIndex(statusList.statusBits, ref.idx, statusList.bitsPerStatus);

            if (status != 0) {
                throw new IllegalStateException(
                        "Credential has been revoked (status=" + status + " at index " + ref.idx + ")");
            }

            LOG.infof("Revocation check passed: status=%d at index %d", status, ref.idx);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            LOG.warnf("Failed to check revocation status from %s: %s", ref.uri, e.getMessage());
            throw new IllegalStateException("Unable to verify credential revocation status: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    StatusReference extractStatusReference(Map<String, Object> claims) {
        if (claims == null) return null;

        Object statusObj = claims.get("status");
        if (statusObj == null) {
            statusObj = findNestedStatusClaim(claims);
        }

        if (!(statusObj instanceof Map<?, ?> statusMap)) return null;

        Object statusListObj = statusMap.get("status_list");
        if (!(statusListObj instanceof Map<?, ?> statusListMap)) return null;

        Object uriObj = statusListMap.get("uri");
        Object idxObj = statusListMap.get("idx");
        if (uriObj == null || idxObj == null) return null;

        String uri = stringValue(uriObj);
        Integer idx = integerValue(idxObj);
        if (uri == null || idx == null) return null;
        return new StatusReference(uri, idx);
    }

    private Object findNestedStatusClaim(Map<String, Object> claims) {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (entry.getKey().endsWith("/status")) {
                return entry.getValue();
            }
        }
        return null;
    }

    DecodedStatusList fetchAndDecodeStatusList(String uri) throws Exception {
        return fetchAndDecodeStatusList(uri, StatusListTrust.trustAnchorsOnly());
    }

    DecodedStatusList fetchAndDecodeStatusList(String uri, StatusListTrust trust) throws Exception {
        CachedStatusList cached = CACHE.get(uri);
        // A list verified with one issuer's own key must not satisfy another issuer's credentials.
        if (cached != null && cached.isValid() && cached.usableFor(issuerDomain(trust))) {
            LOG.debugf("Using cached status list for %s (expires %s)", uri, cached.expiresAt);
            return cached.decoded;
        }

        String jwt = fetchStatusListJwt(uri);
        JWSInput signedJwt = X5cChainValidator.parseJwt(jwt);
        Map<String, Object> claims = X5cChainValidator.parseClaims(signedJwt);

        String trustDomain = verifyStatusListJwtSignature(jwt, trust);

        validateStatusListToken(headerType(signedJwt), stringClaim(claims, "sub"), instantClaim(claims, "exp"), uri);
        Map<String, Object> statusListClaim = jsonObjectClaim(claims, "status_list");
        if (statusListClaim == null) {
            throw new IllegalStateException("Status list JWT missing status_list claim");
        }

        Object lstObj = statusListClaim.get("lst");
        if (!(lstObj instanceof String lst)) {
            throw new IllegalStateException("Status list JWT missing status_list.lst claim");
        }

        int bitsPerStatus = DEFAULT_BITS_PER_STATUS;
        Object bitsObj = statusListClaim.get("bits");
        if (bitsObj instanceof Number num) {
            bitsPerStatus = num.intValue();
        }
        validateBitsPerStatus(bitsPerStatus);

        byte[] compressed = Base64.getUrlDecoder().decode(lst);
        byte[] statusBits = inflate(compressed);

        Instant expiresAt = resolveExpiry(instantClaim(claims, "exp"), claims.get("ttl"));

        var decoded = new DecodedStatusList(statusBits, bitsPerStatus);
        CACHE.put(uri, new CachedStatusList(decoded, expiresAt, trustDomain));
        return decoded;
    }

    /**
     * Verifies the Status List Token signature and returns the trust domain that accepted it. An
     * unverifiable token is always rejected.
     */
    String verifyStatusListJwtSignature(String compactJwt, StatusListTrust trust) {
        List<X509Certificate> anchors = List.of();
        if (trustListProvider != null) {
            anchors = trustListProvider.getRevocationCertificates();
            if (anchors.isEmpty()) {
                anchors = trustListProvider.getIssuanceCertificates();
            }
        }

        Exception anchorFailure = null;
        if (!anchors.isEmpty()) {
            try {
                X5cChainValidator.verifyJwtSignature(compactJwt, anchors);
                return TRUST_ANCHOR_DOMAIN;
            } catch (Exception e) {
                anchorFailure = e;
            }
        }

        if (!trust.issuerVerifiers().isEmpty() && verifyWithIssuerKeys(compactJwt, trust.issuerVerifiers())) {
            return issuerDomain(trust);
        }

        if (anchorFailure != null) {
            throw new IllegalStateException(
                    "Status list token signature is not trusted: " + anchorFailure.getMessage(), anchorFailure);
        }
        throw new IllegalStateException(
                "Status list token signature cannot be verified: no trust anchors or issuer keys available");
    }

    private boolean verifyWithIssuerKeys(String compactJwt, List<SignatureVerifierContext> verifiers) {
        JWSInput jwt = X5cChainValidator.parseJwt(compactJwt);
        String algorithm = jwt.getHeader().getRawAlgorithm();
        byte[] signingInput = jwt.getEncodedSignatureInput().getBytes(StandardCharsets.US_ASCII);
        for (SignatureVerifierContext verifier : verifiers) {
            try {
                if (verifier.getAlgorithm() != null && !verifier.getAlgorithm().equals(algorithm)) {
                    continue;
                }
                if (verifier.verify(signingInput, jwt.getSignature())) {
                    return true;
                }
            } catch (Exception e) {
                LOG.debugf("Status list signature check with issuer key failed: %s", e.getMessage());
            }
        }
        return false;
    }

    private static String issuerDomain(StatusListTrust trust) {
        return trust.issuer() != null ? "issuer:" + trust.issuer() : TRUST_ANCHOR_DOMAIN;
    }

    /**
     * Validates the Status List Token header and claims per draft-ietf-oauth-status-list Section 5.1
     * and Section 8.3.
     */
    void validateStatusListToken(String typ, String sub, Instant exp, String expectedUri) {
        if (!"statuslist+jwt".equals(typ)) {
            throw new IllegalStateException(
                    "Status list JWT has invalid typ header: expected 'statuslist+jwt', got '" + typ + "'");
        }

        if (!expectedUri.equals(sub)) {
            throw new IllegalStateException(
                    "Status list JWT sub claim '" + sub + "' does not match expected URI '" + expectedUri + "'");
        }

        if (exp != null && exp.isBefore(Instant.now())) {
            throw new IllegalStateException("Status list JWT has expired");
        }
    }

    /**
     * Resolves the cache expiry for a Status List Token. Uses {@code ttl} (seconds from fetch time)
     * if present, falls back to {@code exp}, and caps at {@code maxCacheTtl} if configured.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list">Section 13.7</a>
     */
    Instant resolveExpiry(Instant exp, Object ttlObj) {
        Instant now = Instant.now();
        Instant expiry;

        if (ttlObj instanceof Number ttlNum && ttlNum.longValue() > 0) {
            Instant ttlExpiry = now.plusSeconds(ttlNum.longValue());
            expiry = (exp != null && exp.isBefore(ttlExpiry)) ? exp : ttlExpiry;
        } else if (exp != null) {
            expiry = exp;
        } else {
            expiry = now;
        }

        if (maxCacheTtl != null) {
            Instant maxExpiry = now.plus(maxCacheTtl);
            return expiry.isBefore(maxExpiry) ? expiry : maxExpiry;
        }
        return expiry;
    }

    private String fetchStatusListJwt(String uri) throws Exception {
        if (session != null) {
            return SimpleHttp.doGet(uri, session)
                    .header("Accept", "application/statuslist+jwt")
                    .setMaxConsumedResponseSize(MAX_STATUS_LIST_TOKEN_BYTES)
                    .asString();
        }
        // Fallback for tests without KeycloakSession
        throw new IllegalStateException("No KeycloakSession available for HTTP requests");
    }

    static byte[] inflate(byte[] compressed) throws Exception {
        try {
            return inflateBounded(new Inflater(), compressed);
        } catch (DataFormatException e) {
            // Fallback: try raw DEFLATE (without zlib header)
            return inflateBounded(new Inflater(true), compressed);
        }
    }

    /** Inflates with a hard output limit so a small compressed list cannot exhaust memory. */
    private static byte[] inflateBounded(Inflater inflater, byte[] compressed) throws DataFormatException {
        try {
            inflater.setInput(compressed);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(compressed.length * 4, 1 << 20));
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    throw new DataFormatException("Truncated or incomplete DEFLATE stream");
                }
                if (out.size() + n > MAX_DECOMPRESSED_STATUS_LIST_BYTES) {
                    throw new IllegalStateException(
                            "Status list exceeds " + MAX_DECOMPRESSED_STATUS_LIST_BYTES + " bytes when decompressed");
                }
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } finally {
            inflater.end();
        }
    }

    static int getStatusAtIndex(byte[] statusBits, int idx, int bitsPerStatus) {
        if (statusBits == null || statusBits.length == 0) {
            throw new IllegalStateException("Empty status list");
        }
        validateBitsPerStatus(bitsPerStatus);
        int bitOffset = idx * bitsPerStatus;
        int byteIndex = bitOffset / 8;
        int bitIndex = bitOffset % 8;

        if (byteIndex >= statusBits.length) {
            throw new IllegalStateException("Status index " + idx + " out of range (list has "
                    + (statusBits.length * 8 / bitsPerStatus) + " entries)");
        }

        int mask = ((1 << bitsPerStatus) - 1);
        int byteValue = Byte.toUnsignedInt(statusBits[byteIndex]);
        return (byteValue >>> bitIndex) & mask;
    }

    private static void validateBitsPerStatus(int bitsPerStatus) {
        if (bitsPerStatus != 1 && bitsPerStatus != 2 && bitsPerStatus != 4 && bitsPerStatus != 8) {
            throw new IllegalArgumentException("bitsPerStatus must be one of 1, 2, 4, or 8, got " + bitsPerStatus);
        }
    }

    /** Clears the static cache. Intended for testing only. */
    static void clearCache() {
        CACHE.clear();
    }

    record StatusReference(String uri, int idx) {}

    record DecodedStatusList(byte[] statusBits, int bitsPerStatus) {}

    private record CachedStatusList(DecodedStatusList decoded, Instant expiresAt, String trustDomain) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }

        boolean usableFor(String domain) {
            return TRUST_ANCHOR_DOMAIN.equals(trustDomain) || trustDomain.equals(domain);
        }
    }

    private String headerType(JWSInput jwt) {
        return jwt.getHeader().getType();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> jsonObjectClaim(Map<String, Object> claims, String name) {
        Object value = claims.get(name);
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : null;
    }

    private String stringClaim(Map<String, Object> claims, String name) {
        return stringValue(claims.get(name));
    }

    private Instant instantClaim(Map<String, Object> claims, String name) {
        Long epochSeconds = longValue(claims.get(name));
        if (epochSeconds != null) {
            return Instant.ofEpochSecond(epochSeconds);
        }
        return null;
    }

    private String stringValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof JsonNode jsonNode) {
            return jsonNode.isTextual() ? jsonNode.textValue() : null;
        }
        return value.toString();
    }

    private Integer integerValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        Long longValue = longValue(value);
        if (longValue == null) {
            return null;
        }
        try {
            return Math.toIntExact(longValue);
        } catch (ArithmeticException e) {
            return null;
        }
    }

    private Long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof JsonNode jsonNode) {
            if (jsonNode.isIntegralNumber()) {
                return jsonNode.longValue();
            }
            if (jsonNode.isTextual()) {
                try {
                    return Long.parseLong(jsonNode.textValue());
                } catch (NumberFormatException e) {
                    return null;
                }
            }
            return null;
        }
        if (value != null) {
            try {
                return Long.parseLong(value.toString());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}
