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

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORLong;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.authlete.cose.SigStructureBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.connections.httpclient.HttpClientProvider;
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
    static final int MAX_CACHED_LISTS = 256;
    static final long MAX_CACHED_BYTES = 128L * 1024 * 1024;

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
        if (statusListObj == null) return null; // another status mechanism, not checked here
        // A status_list reference that cannot be read must not pass as "not revoked".
        if (!(statusListObj instanceof Map<?, ?> statusListMap)) {
            throw new IdentityBrokerException("Malformed status_list reference");
        }
        String uri = stringValue(statusListMap.get("uri"));
        Long idx = longValue(statusListMap.get("idx"));
        if (uri == null || uri.isBlank() || idx == null || idx < 0 || idx > Integer.MAX_VALUE) {
            throw new IdentityBrokerException("Malformed status_list reference");
        }
        return new StatusReference(uri, idx.intValue());
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

        FetchedStatusList fetched = fetchStatusList(uri);
        ParsedStatusList parsed = fetched.isCwt()
                ? decodeCwtStatusList(fetched.body(), uri, trust)
                : decodeJwtStatusList(new String(fetched.body(), StandardCharsets.US_ASCII).trim(), uri, trust);

        validateBitsPerStatus(parsed.bitsPerStatus());
        byte[] statusBits = inflate(parsed.compressed());
        Instant expiresAt = resolveExpiry(parsed.exp(), parsed.ttl());

        var decoded = new DecodedStatusList(statusBits, parsed.bitsPerStatus());
        CACHE.put(uri, new CachedStatusList(decoded, expiresAt, parsed.trustDomain()));
        evictBeyondBudget();
        return decoded;
    }

    /**
     * Status list URIs come from presented credentials, so the cache is bounded: expired entries go
     * first, then those expiring soonest, until the decompressed lists fit the budget.
     */
    private static synchronized void evictBeyondBudget() {
        CACHE.entrySet().removeIf(entry -> !entry.getValue().isValid());
        while (CACHE.size() > MAX_CACHED_LISTS || cachedBytes() > MAX_CACHED_BYTES) {
            var soonest = CACHE.entrySet().stream().min(java.util.Comparator.comparing(entry -> entry.getValue()
                    .expiresAt()));
            if (soonest.isEmpty()) return;
            CACHE.remove(soonest.get().getKey());
        }
    }

    private static long cachedBytes() {
        long total = 0;
        for (CachedStatusList entry : CACHE.values()) total += entry.decoded().statusBits().length;
        return total;
    }

    /** A verified Status List Token, before decompression. */
    record ParsedStatusList(byte[] compressed, int bitsPerStatus, Instant exp, Object ttl, String trustDomain) {}

    /** Verifies and parses a Status List Token in JWT form ({@code application/statuslist+jwt}). */
    ParsedStatusList decodeJwtStatusList(String jwt, String uri, StatusListTrust trust) {
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
        return new ParsedStatusList(
                Base64.getUrlDecoder().decode(lst),
                bitsPerStatus,
                instantClaim(claims, "exp"),
                claims.get("ttl"),
                trustDomain);
    }

    // CWT claim keys (RFC 8392 and draft-ietf-oauth-status-list)
    private static final int CWT_SUB = 2;
    private static final int CWT_EXP = 4;
    private static final int CWT_TTL = 65534;
    private static final int CWT_STATUS_LIST = 65533;
    private static final int COSE_HEADER_TYP = 16;
    static final String STATUS_LIST_CWT_TYPE = "application/statuslist+cwt";

    /** Verifies and parses a Status List Token in CWT form ({@code application/statuslist+cwt}). */
    ParsedStatusList decodeCwtStatusList(byte[] cwt, String uri, StatusListTrust trust) {
        COSESign1 sign1;
        CBORPairList claims;
        try {
            CBORItem item = new CBORDecoder(cwt).next();
            if (item instanceof CBORTaggedItem tagged && tagged.getTagNumber().intValue() == 18) {
                item = tagged.getTagContent();
            }
            sign1 = COSESign1.build(item);
            if (!(sign1.getPayload() instanceof CBORByteArray payload)) {
                throw new IllegalStateException("Status list CWT has no payload");
            }
            if (!(new CBORDecoder(payload.getValue()).next() instanceof CBORPairList map)) {
                throw new IllegalStateException("Status list CWT payload is not a claims map");
            }
            claims = map;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse status list CWT: " + e.getMessage(), e);
        }

        Object typ = sign1.getProtectedHeader().getParameters().get(COSE_HEADER_TYP);
        String trustDomain = verifyStatusListCwtSignature(sign1, trust);

        Instant exp = cwtInstant(cwtClaim(claims, CWT_EXP));
        if (!STATUS_LIST_CWT_TYPE.equals(typ)) {
            throw new IllegalStateException("Status list CWT has invalid typ header: expected '" + STATUS_LIST_CWT_TYPE
                    + "', got '" + typ + "'");
        }
        validateStatusListClaims(cwtClaim(claims, CWT_SUB) instanceof CBORString sub ? sub.getValue() : null, exp, uri);

        if (!(cwtClaim(claims, CWT_STATUS_LIST) instanceof CBORPairList statusList)) {
            throw new IllegalStateException("Status list CWT missing status_list claim");
        }
        CBORItem lst = null;
        CBORItem bits = null;
        for (CBORPair pair : statusList.getPairs()) {
            if (pair.getKey() instanceof CBORString key) {
                if ("lst".equals(key.getValue())) lst = pair.getValue();
                if ("bits".equals(key.getValue())) bits = pair.getValue();
            }
        }
        if (!(lst instanceof CBORByteArray compressed)) {
            throw new IllegalStateException("Status list CWT missing status_list.lst byte string");
        }
        Long bitsValue = cwtLong(bits);
        Long ttl = cwtLong(cwtClaim(claims, CWT_TTL));
        return new ParsedStatusList(
                compressed.getValue(),
                bitsValue != null ? Math.toIntExact(bitsValue) : DEFAULT_BITS_PER_STATUS,
                exp,
                ttl,
                trustDomain);
    }

    /**
     * Verifies a CWT Status List Token: an {@code x5chain} must validate against the trust anchors;
     * without one, a currently valid anchor's key or one of the referenced credential's issuer keys
     * must verify the signature.
     */
    String verifyStatusListCwtSignature(COSESign1 sign1, StatusListTrust trust) {
        List<X509Certificate> anchors = statusListTrustAnchors();
        List<X509Certificate> x5chain = sign1.getProtectedHeader().getX5Chain();
        if ((x5chain == null || x5chain.isEmpty()) && sign1.getUnprotectedHeader() != null) {
            x5chain = sign1.getUnprotectedHeader().getX5Chain();
        }

        Exception anchorFailure = null;
        if (!anchors.isEmpty()) {
            try {
                if (x5chain != null && !x5chain.isEmpty()) {
                    PublicKey leafKey = X5cChainValidator.validateCertChain(x5chain, anchors);
                    if (new COSEVerifier(leafKey).verify(sign1)) return TRUST_ANCHOR_DOMAIN;
                    throw new IllegalStateException("signature does not verify with the x5chain leaf key");
                }
                for (X509Certificate anchor : X5cChainValidator.currentlyValid(anchors)) {
                    try {
                        if (new COSEVerifier(anchor.getPublicKey()).verify(sign1)) return TRUST_ANCHOR_DOMAIN;
                    } catch (Exception ignored) {
                        // try the next anchor
                    }
                }
                throw new IllegalStateException("no trusted key matched");
            } catch (Exception e) {
                anchorFailure = e;
            }
        }

        if (!trust.issuerVerifiers().isEmpty() && verifyCwtWithIssuerKeys(sign1, trust.issuerVerifiers())) {
            return issuerDomain(trust);
        }
        if (anchorFailure != null) {
            throw new IllegalStateException(
                    "Status list token signature is not trusted: " + anchorFailure.getMessage(), anchorFailure);
        }
        throw new IllegalStateException(
                "Status list token signature cannot be verified: no trust anchors or issuer keys available");
    }

    private boolean verifyCwtWithIssuerKeys(COSESign1 sign1, List<SignatureVerifierContext> verifiers) {
        String algorithm = joseAlgorithm(sign1.getProtectedHeader().getAlg());
        byte[] toBeSigned = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(sign1.getProtectedHeader())
                .payload((CBORByteArray) sign1.getPayload())
                .build()
                .encode();
        for (SignatureVerifierContext verifier : verifiers) {
            try {
                if (verifier.getAlgorithm() != null && !verifier.getAlgorithm().equals(algorithm)) continue;
                if (verifier.verify(toBeSigned, sign1.getSignature().getValue())) return true;
            } catch (Exception e) {
                LOG.debugf("Status list CWT check with issuer key failed: %s", e.getMessage());
            }
        }
        return false;
    }

    private static String joseAlgorithm(Object coseAlg) {
        if (!(coseAlg instanceof Number number)) return null;
        return switch (number.intValue()) {
            case -7 -> "ES256";
            case -35 -> "ES384";
            case -36 -> "ES512";
            case -8 -> "EdDSA";
            case -37 -> "PS256";
            case -38 -> "PS384";
            case -39 -> "PS512";
            default -> null;
        };
    }

    private List<X509Certificate> statusListTrustAnchors() {
        if (trustListProvider == null) return List.of();
        List<X509Certificate> anchors = trustListProvider.getRevocationCertificates();
        return anchors.isEmpty() ? trustListProvider.getIssuanceCertificates() : anchors;
    }

    private static CBORItem cwtClaim(CBORPairList claims, int key) {
        for (CBORPair pair : claims.getPairs()) {
            Long k = cwtLong(pair.getKey());
            if (k != null && k == key) return pair.getValue();
        }
        return null;
    }

    private static Long cwtLong(CBORItem item) {
        if (item instanceof CBORInteger i) return (long) i.getValue();
        if (item instanceof CBORLong l) return l.getValue();
        return null;
    }

    private static Instant cwtInstant(CBORItem item) {
        Long seconds = cwtLong(item);
        return seconds != null ? Instant.ofEpochSecond(seconds) : null;
    }

    /**
     * Verifies the Status List Token signature and returns the trust domain that accepted it. An
     * unverifiable token is always rejected.
     */
    String verifyStatusListJwtSignature(String compactJwt, StatusListTrust trust) {
        List<X509Certificate> anchors = statusListTrustAnchors();

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
        validateStatusListClaims(sub, exp, expectedUri);
    }

    /** Validates the claims shared by the JWT and CWT forms: {@code sub} and {@code exp}. */
    void validateStatusListClaims(String sub, Instant exp, String expectedUri) {
        if (!expectedUri.equals(sub)) {
            throw new IllegalStateException(
                    "Status list token sub claim '" + sub + "' does not match expected URI '" + expectedUri + "'");
        }

        if (exp != null && exp.isBefore(Instant.now())) {
            throw new IllegalStateException("Status list token has expired");
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

    /** A fetched Status List Token and its media type. */
    record FetchedStatusList(byte[] body, String contentType) {
        /** CWT when the server says so, or when the body is binary CBOR rather than a compact JWS. */
        boolean isCwt() {
            if (contentType != null) {
                String type = contentType.toLowerCase();
                if (type.startsWith(STATUS_LIST_CWT_TYPE)) return true;
                if (type.startsWith("application/statuslist+jwt")) return false;
            }
            return body.length > 0 && (body[0] & 0xff) != 'e' && !Character.isWhitespace(body[0]);
        }
    }

    FetchedStatusList fetchStatusList(String uri) throws Exception {
        if (session == null) {
            throw new IllegalStateException("No KeycloakSession available for HTTP requests");
        }
        // The status list URI comes from the presented credential.
        io.github.suengineering.keycloak.oid4vp.util.OutboundUrlPolicy.check(session, uri);
        HttpGet get = new HttpGet(uri);
        get.setHeader("Accept", "application/statuslist+jwt, " + STATUS_LIST_CWT_TYPE);
        try (CloseableHttpResponse response =
                session.getProvider(HttpClientProvider.class).getHttpClient().execute(get)) {
            int status = response.getStatusLine().getStatusCode();
            if (status != 200) {
                throw new IllegalStateException("Status list fetch returned HTTP " + status);
            }
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                throw new IllegalStateException("Status list response has no body");
            }
            byte[] body;
            try (InputStream in = entity.getContent()) {
                body = in.readNBytes((int) MAX_STATUS_LIST_TOKEN_BYTES + 1);
            }
            if (body.length > MAX_STATUS_LIST_TOKEN_BYTES) {
                throw new IllegalStateException("Status list token exceeds " + MAX_STATUS_LIST_TOKEN_BYTES + " bytes");
            }
            return new FetchedStatusList(
                    body,
                    entity.getContentType() != null ? entity.getContentType().getValue() : null);
        }
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
        if (idx < 0) {
            throw new IllegalStateException("Status index " + idx + " is negative");
        }
        long bitOffset = (long) idx * bitsPerStatus;
        long byteOffset = bitOffset / 8;
        int bitIndex = (int) (bitOffset % 8);

        if (byteOffset >= statusBits.length) {
            throw new IllegalStateException("Status index " + idx + " out of range (list has "
                    + (statusBits.length * 8 / bitsPerStatus) + " entries)");
        }

        int mask = ((1 << bitsPerStatus) - 1);
        int byteValue = Byte.toUnsignedInt(statusBits[(int) byteOffset]);
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
