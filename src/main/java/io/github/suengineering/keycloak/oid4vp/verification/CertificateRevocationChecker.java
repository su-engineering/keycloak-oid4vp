/*
 * Copyright 2026 su-engineering
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

/**
 * Checks the revocation status of the certificates in a validated issuer chain, below its trust
 * anchor: OCSP from the authority information access extension first, then the CRL distribution
 * points. OCSP responses and CRLs must be signed by the issuing CA, or (OCSP) by a responder
 * certificate that CA issued for OCSP signing, and must be current.
 *
 * <p>{@link Mode#SOFT} rejects revoked certificates and accepts those whose status cannot be
 * determined; {@link Mode#STRICT} rejects both.
 */
public class CertificateRevocationChecker {

    public enum Mode {
        NONE("none"),
        SOFT("soft"),
        STRICT("strict");

        private final String configValue;

        Mode(String configValue) {
            this.configValue = configValue;
        }

        public String configValue() {
            return configValue;
        }

        public static Mode resolve(String value) {
            for (Mode mode : values()) {
                if (mode.configValue.equalsIgnoreCase(value == null ? "" : value.trim())) return mode;
            }
            return NONE;
        }
    }

    enum Status {
        GOOD,
        REVOKED,
        UNKNOWN
    }

    public static final CertificateRevocationChecker DISABLED = new CertificateRevocationChecker(null, Mode.NONE);

    private static final Logger LOG = Logger.getLogger(CertificateRevocationChecker.class);
    private static final int MAX_CRL_BYTES = 10 * 1024 * 1024;
    private static final int MAX_OCSP_BYTES = 1024 * 1024;
    private static final Duration MAX_CACHE = Duration.ofHours(24);
    private static final Duration UNDATED_OCSP_CACHE = Duration.ofMinutes(5);
    private static final Duration MAX_UNDATED_AGE = Duration.ofDays(7);
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    private static final Map<String, CachedCrl> CRL_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, CachedStatus> OCSP_CACHE = new ConcurrentHashMap<>();

    private static final byte[] OID_OCSP = oid("1.3.6.1.5.5.7.48.1");
    private static final byte[] OID_OCSP_BASIC = oid("1.3.6.1.5.5.7.48.1.1");
    private static final byte[] OID_SHA1 = oid("1.3.14.3.2.26");
    private static final byte[] OID_SHA256 = oid("2.16.840.1.101.3.4.2.1");
    private static final String EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    private final KeycloakSession session;
    private final Mode mode;
    private final Clock clock;

    private record CachedCrl(X509CRL crl, Instant expiresAt) {}

    private record CachedStatus(Status status, Instant expiresAt) {}

    public CertificateRevocationChecker(KeycloakSession session, Mode mode) {
        this(session, mode, Clock.systemUTC());
    }

    CertificateRevocationChecker(KeycloakSession session, Mode mode, Clock clock) {
        this.session = session;
        this.mode = mode != null ? mode : Mode.NONE;
        this.clock = clock;
    }

    public Mode mode() {
        return mode;
    }

    /** Checks every certificate below the anchor; throws when the mode does not accept the result. */
    void check(X5cChainValidator.AnchoredChain chain) {
        if (mode == Mode.NONE) return;
        List<X509Certificate> certificates = chain.belowAnchor();
        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate certificate = certificates.get(i);
            X509Certificate issuer = i + 1 < certificates.size() ? certificates.get(i + 1) : chain.anchor();
            Status status = status(certificate, issuer);
            String subject = certificate.getSubjectX500Principal().getName();
            if (status == Status.REVOKED) {
                throw new IllegalStateException("Certificate is revoked: " + subject);
            }
            if (status == Status.UNKNOWN) {
                if (mode == Mode.STRICT) {
                    throw new IllegalStateException("Revocation status cannot be determined: " + subject);
                }
                LOG.warnf("Revocation status of %s cannot be determined; accepted in soft mode", subject);
            }
        }
    }

    Status status(X509Certificate certificate, X509Certificate issuer) {
        for (String url : ocspUrls(certificate)) {
            Status status = ocspStatus(url, certificate, issuer);
            if (status != Status.UNKNOWN) return status;
        }
        for (String url : crlUrls(certificate)) {
            Status status = crlStatus(url, certificate, issuer);
            if (status != Status.UNKNOWN) return status;
        }
        return Status.UNKNOWN;
    }

    // --- CRL ---

    private Status crlStatus(String url, X509Certificate certificate, X509Certificate issuer) {
        try {
            X509CRL crl = crl(url, issuer);
            return crl.isRevoked(certificate) ? Status.REVOKED : Status.GOOD;
        } catch (Exception e) {
            LOG.debugf("CRL %s unusable for %s: %s", url, certificate.getSubjectX500Principal(), e.getMessage());
            return Status.UNKNOWN;
        }
    }

    private X509CRL crl(String url, X509Certificate issuer) throws Exception {
        Instant now = clock.instant();
        CachedCrl cached = CRL_CACHE.get(url);
        if (cached != null && now.isBefore(cached.expiresAt())) {
            verifyCrl(cached.crl(), issuer, now);
            return cached.crl();
        }
        X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
                .generateCRL(new ByteArrayInputStream(fetch(new HttpGet(url), MAX_CRL_BYTES)));
        verifyCrl(crl, issuer, now);
        Instant expires = now.plus(MAX_CACHE);
        if (crl.getNextUpdate() != null && crl.getNextUpdate().toInstant().isBefore(expires)) {
            expires = crl.getNextUpdate().toInstant();
        }
        CRL_CACHE.put(url, new CachedCrl(crl, expires));
        return crl;
    }

    private void verifyCrl(X509CRL crl, X509Certificate issuer, Instant now) throws Exception {
        if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            throw new IllegalStateException("CRL issued by " + crl.getIssuerX500Principal());
        }
        crl.verify(issuer.getPublicKey());
        if (crl.getThisUpdate().toInstant().isAfter(now.plus(CLOCK_SKEW))) {
            throw new IllegalStateException("CRL is not yet valid");
        }
        if (crl.getNextUpdate() != null
                ? !now.isBefore(crl.getNextUpdate().toInstant())
                : crl.getThisUpdate().toInstant().plus(MAX_UNDATED_AGE).isBefore(now)) {
            throw new IllegalStateException("CRL is outdated");
        }
    }

    // --- OCSP ---

    private Status ocspStatus(String url, X509Certificate certificate, X509Certificate issuer) {
        try {
            String cacheKey = url + "|" + certificate.getSerialNumber() + "|" + hex(keyHash(issuer, "SHA-1"));
            Instant now = clock.instant();
            CachedStatus cached = OCSP_CACHE.get(cacheKey);
            if (cached != null && now.isBefore(cached.expiresAt())) return cached.status();

            HttpPost post = new HttpPost(url);
            post.setEntity(new ByteArrayEntity(
                    ocspRequest(certificate, issuer), ContentType.create("application/ocsp-request")));
            post.setHeader("Accept", "application/ocsp-response");
            Single single = parseOcspResponse(fetch(post, MAX_OCSP_BYTES), certificate, issuer, now);
            Instant expires = single.nextUpdate() != null ? single.nextUpdate() : now.plus(UNDATED_OCSP_CACHE);
            if (expires.isAfter(now.plus(MAX_CACHE))) expires = now.plus(MAX_CACHE);
            OCSP_CACHE.put(cacheKey, new CachedStatus(single.status(), expires));
            return single.status();
        } catch (Exception e) {
            LOG.debugf("OCSP %s unusable for %s: %s", url, certificate.getSubjectX500Principal(), e.getMessage());
            return Status.UNKNOWN;
        }
    }

    record Single(Status status, Instant nextUpdate) {}

    /** OCSPRequest with one request for {@code certificate}, CertID hashed with SHA-1 (RFC 6960). */
    static byte[] ocspRequest(X509Certificate certificate, X509Certificate issuer) throws Exception {
        byte[] certId = seq(certId(certificate, issuer));
        byte[] request = seq(certId);
        byte[] requestList = seq(request);
        byte[] tbsRequest = seq(requestList);
        return seq(tbsRequest); // OCSPRequest
    }

    private static byte[] certId(X509Certificate certificate, X509Certificate issuer) throws Exception {
        byte[] algorithm = seq(tlv(0x06, OID_SHA1), new byte[] {0x05, 0x00});
        byte[] nameHash = MessageDigest.getInstance("SHA-1")
                .digest(issuer.getSubjectX500Principal().getEncoded());
        return concat(
                algorithm,
                tlv(0x04, nameHash),
                tlv(0x04, keyHash(issuer, "SHA-1")),
                tlv(0x02, certificate.getSerialNumber().toByteArray()));
    }

    static Single parseOcspResponse(byte[] response, X509Certificate certificate, X509Certificate issuer, Instant now)
            throws Exception {
        Der root = Der.parse(response);
        List<Der> top = root.children();
        if (top.isEmpty()
                || top.get(0).tag() != 0x0A
                || top.get(0).content().length != 1
                || top.get(0).content()[0] != 0) {
            throw new IllegalStateException("OCSP responder did not answer successfully");
        }
        Der responseBytes = top.get(1).children().get(0); // [0] EXPLICIT ResponseBytes
        if (!Arrays.equals(responseBytes.children().get(0).content(), OID_OCSP_BASIC)) {
            throw new IllegalStateException("Not a basic OCSP response");
        }
        Der basic = Der.parse(responseBytes.children().get(1).content());
        List<Der> basicParts = basic.children();
        Der tbs = basicParts.get(0);
        String signatureAlgorithm =
                signatureAlgorithm(basicParts.get(1).children().get(0).content());
        byte[] signatureBits = basicParts.get(2).content();
        byte[] signature = Arrays.copyOfRange(signatureBits, 1, signatureBits.length);
        List<X509Certificate> responderCerts = new ArrayList<>();
        if (basicParts.size() > 3 && basicParts.get(3).tag() == 0xA0) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (Der cert : basicParts.get(3).children().get(0).children()) {
                responderCerts.add(
                        (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert.encoded())));
            }
        }
        if (!signedByIssuerOrDelegate(tbs.encoded(), signatureAlgorithm, signature, issuer, responderCerts, now)) {
            throw new IllegalStateException("OCSP response signature does not verify");
        }

        List<Der> data = tbs.children();
        int index = data.get(0).tag() == 0xA0 ? 1 : 0; // optional version
        index += 2; // responderID, producedAt
        for (Der single : data.get(index).children()) {
            List<Der> parts = single.children();
            if (!matches(parts.get(0), certificate, issuer)) continue;
            Der certStatus = parts.get(1);
            Instant thisUpdate = generalizedTime(parts.get(2).content());
            Instant nextUpdate = null;
            for (int i = 3; i < parts.size(); i++) {
                if (parts.get(i).tag() == 0xA0)
                    nextUpdate = generalizedTime(parts.get(i).children().get(0).content());
            }
            if (thisUpdate.isAfter(now.plus(CLOCK_SKEW)))
                throw new IllegalStateException("OCSP response from the future");
            if (nextUpdate != null
                    ? now.isAfter(nextUpdate.plus(CLOCK_SKEW))
                    : thisUpdate.plus(MAX_UNDATED_AGE).isBefore(now)) {
                throw new IllegalStateException("OCSP response is outdated");
            }
            Status status =
                    switch (certStatus.tag()) {
                        case 0x80 -> Status.GOOD;
                        case 0xA1 -> Status.REVOKED;
                        default -> Status.UNKNOWN;
                    };
            return new Single(status, nextUpdate);
        }
        throw new IllegalStateException("OCSP response does not cover the certificate");
    }

    private static boolean matches(Der certId, X509Certificate certificate, X509Certificate issuer) throws Exception {
        List<Der> parts = certId.children();
        byte[] algorithm = parts.get(0).children().get(0).content();
        String digest =
                Arrays.equals(algorithm, OID_SHA1) ? "SHA-1" : Arrays.equals(algorithm, OID_SHA256) ? "SHA-256" : null;
        if (digest == null) return false;
        return Arrays.equals(
                        parts.get(1).content(),
                        MessageDigest.getInstance(digest)
                                .digest(issuer.getSubjectX500Principal().getEncoded()))
                && Arrays.equals(parts.get(2).content(), keyHash(issuer, digest))
                && new BigInteger(parts.get(3).content()).equals(certificate.getSerialNumber());
    }

    private static boolean signedByIssuerOrDelegate(
            byte[] tbs,
            String algorithm,
            byte[] signature,
            X509Certificate issuer,
            List<X509Certificate> responders,
            Instant now)
            throws Exception {
        if (algorithm == null) return false;
        if (verify(algorithm, issuer.getPublicKey(), tbs, signature)) return true;
        // RFC 6960 4.2.2.2: a delegated responder certificate issued by the CA for OCSP signing.
        for (X509Certificate responder : responders) {
            try {
                responder.verify(issuer.getPublicKey());
                responder.checkValidity(java.util.Date.from(now));
                List<String> eku = responder.getExtendedKeyUsage();
                if (eku != null
                        && eku.contains(EKU_OCSP_SIGNING)
                        && verify(algorithm, responder.getPublicKey(), tbs, signature)) {
                    return true;
                }
            } catch (Exception ignored) {
                // not a valid delegate
            }
        }
        return false;
    }

    private static boolean verify(String algorithm, PublicKey key, byte[] data, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private static String signatureAlgorithm(byte[] oid) {
        return switch (oidString(oid)) {
            case "1.2.840.113549.1.1.5" -> "SHA1withRSA";
            case "1.2.840.113549.1.1.11" -> "SHA256withRSA";
            case "1.2.840.113549.1.1.12" -> "SHA384withRSA";
            case "1.2.840.113549.1.1.13" -> "SHA512withRSA";
            case "1.2.840.10045.4.3.2" -> "SHA256withECDSA";
            case "1.2.840.10045.4.3.3" -> "SHA384withECDSA";
            case "1.2.840.10045.4.3.4" -> "SHA512withECDSA";
            default -> null;
        };
    }

    // --- extensions ---

    static List<String> ocspUrls(X509Certificate certificate) {
        List<String> urls = new ArrayList<>();
        byte[] extension = certificate.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (extension == null) return urls;
        try {
            for (Der description : Der.parse(Der.parse(extension).content()).children()) {
                List<Der> parts = description.children();
                if (Arrays.equals(parts.get(0).content(), OID_OCSP)
                        && parts.get(1).tag() == 0x86) {
                    urls.add(new String(parts.get(1).content(), StandardCharsets.US_ASCII));
                }
            }
        } catch (Exception e) {
            LOG.debugf("Unreadable authority information access: %s", e.getMessage());
        }
        return httpOnly(urls);
    }

    static List<String> crlUrls(X509Certificate certificate) {
        List<String> urls = new ArrayList<>();
        byte[] extension = certificate.getExtensionValue("2.5.29.31");
        if (extension == null) return urls;
        try {
            collectUris(Der.parse(Der.parse(extension).content()), urls);
        } catch (Exception e) {
            LOG.debugf("Unreadable CRL distribution points: %s", e.getMessage());
        }
        return httpOnly(urls);
    }

    private static void collectUris(Der der, List<String> out) {
        if (der.tag() == 0x86) {
            out.add(new String(der.content(), StandardCharsets.US_ASCII));
            return;
        }
        if (der.constructed()) {
            for (Der child : der.children()) collectUris(child, out);
        }
    }

    private static List<String> httpOnly(List<String> urls) {
        return urls.stream()
                .filter(url -> url.toLowerCase(Locale.ROOT).startsWith("http://")
                        || url.toLowerCase(Locale.ROOT).startsWith("https://"))
                .toList();
    }

    // --- HTTP ---

    byte[] fetch(HttpUriRequest request, int maxBytes) throws Exception {
        if (session == null) throw new IllegalStateException("No KeycloakSession available for HTTP requests");
        try (CloseableHttpResponse response =
                session.getProvider(HttpClientProvider.class).getHttpClient().execute(request)) {
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new IllegalStateException(
                        "HTTP " + response.getStatusLine().getStatusCode());
            }
            HttpEntity entity = response.getEntity();
            if (entity == null) throw new IllegalStateException("empty response");
            try (InputStream in = entity.getContent()) {
                byte[] body = in.readNBytes(maxBytes + 1);
                if (body.length > maxBytes) throw new IllegalStateException("response exceeds " + maxBytes + " bytes");
                return body;
            }
        }
    }

    static void clearCaches() {
        CRL_CACHE.clear();
        OCSP_CACHE.clear();
    }

    // --- DER helpers ---

    /** SHA hash of the issuer's subjectPublicKey BIT STRING value, as in an OCSP CertID. */
    private static byte[] keyHash(X509Certificate issuer, String digest) throws Exception {
        List<Der> spki = Der.parse(issuer.getPublicKey().getEncoded()).children();
        byte[] bits = spki.get(1).content();
        return MessageDigest.getInstance(digest).digest(Arrays.copyOfRange(bits, 1, bits.length));
    }

    private static Instant generalizedTime(byte[] value) {
        String text = new String(value, StandardCharsets.US_ASCII).replace("Z", "");
        int dot = text.indexOf('.');
        if (dot >= 0) text = text.substring(0, dot);
        return LocalDateTime.parse(text, DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
                .toInstant(ZoneOffset.UTC);
    }

    record Der(int tag, byte[] content, byte[] encoded) {
        boolean constructed() {
            return (tag & 0x20) != 0;
        }

        static Der parse(byte[] bytes) {
            return read(bytes, 0);
        }

        private static Der read(byte[] bytes, int offset) {
            int tag = bytes[offset] & 0xff;
            int lengthByte = bytes[offset + 1] & 0xff;
            int length;
            int header = 2;
            if (lengthByte < 0x80) {
                length = lengthByte;
            } else {
                int count = lengthByte & 0x7f;
                if (count == 0 || count > 4) throw new IllegalStateException("Unsupported DER length");
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | (bytes[offset + 2 + i] & 0xff);
                header += count;
            }
            if (length < 0 || offset + header + length > bytes.length) throw new IllegalStateException("Truncated DER");
            return new Der(
                    tag,
                    Arrays.copyOfRange(bytes, offset + header, offset + header + length),
                    Arrays.copyOfRange(bytes, offset, offset + header + length));
        }

        List<Der> children() {
            List<Der> out = new ArrayList<>();
            int offset = 0;
            while (offset < content.length) {
                Der child = read(content, offset);
                out.add(child);
                offset += child.encoded().length;
            }
            return out;
        }
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = value.length;
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else {
            out.write(0x82);
            out.write(length >> 8);
            out.write(length & 0xff);
        }
        out.writeBytes(value);
        return out.toByteArray();
    }

    private static byte[] seq(byte[]... parts) {
        return tlv(0x30, concat(parts));
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.writeBytes(part);
        return out.toByteArray();
    }

    /** DER content octets of an OBJECT IDENTIFIER. */
    static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(arcs[0]) * 40 + Integer.parseInt(arcs[1]));
        for (int i = 2; i < arcs.length; i++) {
            long arc = Long.parseLong(arcs[i]);
            byte[] buffer = new byte[10];
            int n = 0;
            do {
                buffer[n++] = (byte) (arc & 0x7f);
                arc >>= 7;
            } while (arc > 0);
            for (int j = n - 1; j >= 0; j--) out.write(buffer[j] | (j > 0 ? 0x80 : 0));
        }
        return out.toByteArray();
    }

    static String oidString(byte[] content) {
        StringBuilder out = new StringBuilder();
        out.append(content[0] / 40).append('.').append(content[0] % 40);
        long arc = 0;
        for (int i = 1; i < content.length; i++) {
            arc = (arc << 7) | (content[i] & 0x7f);
            if ((content[i] & 0x80) == 0) {
                out.append('.').append(arc);
                arc = 0;
            }
        }
        return out.toString();
    }

    private static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }
}
