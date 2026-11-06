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

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

/**
 * Supplies mDoc trust anchors from a VICAL (Verified Issuer Certificate Authority List, as
 * published by AAMVA for US mobile driving licences).
 *
 * <p>A VICAL is a COSE_Sign1 whose payload is a CBOR map with {@code certificateInfos}; each entry
 * holds an IACA {@code certificate} and the {@code docType}s it may issue. The signature must verify
 * with an {@code x5chain} anchored in the configured VICAL signing certificates. An IACA only anchors
 * documents of the docTypes its entry lists.
 */
public class VicalProvider {

    private static final Logger LOG = Logger.getLogger(VicalProvider.class);
    static final int MAX_VICAL_BYTES = 8 * 1024 * 1024;
    private static final Duration DEFAULT_CACHE_TTL = Duration.ofHours(24);
    private static final Map<String, CachedVical> CACHE = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final String url;
    private final List<X509Certificate> signingCertificates;
    private final Duration maxStaleAge;
    private final Clock clock;

    /** An IACA from the VICAL and the docTypes it may issue. */
    public record Entry(X509Certificate certificate, List<String> docTypes) {}

    record Vical(List<Entry> entries, Instant nextUpdate, Instant notAfter) {}

    private record CachedVical(Vical vical, Instant fetchedAt, Instant expiresAt) {}

    public VicalProvider(
            KeycloakSession session, String url, List<X509Certificate> signingCertificates, Duration maxStaleAge) {
        this(session, url, signingCertificates, maxStaleAge, Clock.systemUTC());
    }

    VicalProvider(
            KeycloakSession session,
            String url,
            List<X509Certificate> signingCertificates,
            Duration maxStaleAge,
            Clock clock) {
        this.session = session;
        this.url = url;
        this.signingCertificates = signingCertificates != null ? signingCertificates : List.of();
        this.maxStaleAge = maxStaleAge != null ? maxStaleAge : Duration.ZERO;
        this.clock = clock;
    }

    /** IACA certificates allowed to anchor a document of {@code docType}; empty when there is none. */
    public List<X509Certificate> anchorsFor(String docType) {
        if (docType == null) return List.of();
        List<X509Certificate> anchors = new ArrayList<>();
        for (Entry entry : current().entries()) {
            if (entry.docTypes().contains(docType)) anchors.add(entry.certificate());
        }
        return anchors;
    }

    private Vical current() {
        Instant now = clock.instant();
        CachedVical cached = CACHE.get(url);
        if (cached != null && now.isBefore(cached.expiresAt())) {
            return cached.vical();
        }
        try {
            Vical vical = parse(fetch(), signingCertificates, now);
            Instant expires = now.plus(DEFAULT_CACHE_TTL);
            if (vical.nextUpdate() != null && vical.nextUpdate().isBefore(expires)) {
                expires = vical.nextUpdate().isAfter(now) ? vical.nextUpdate() : now;
            }
            CACHE.put(url, new CachedVical(vical, now, expires));
            return vical;
        } catch (Exception e) {
            if (cached != null
                    && now.isBefore(cached.fetchedAt().plus(maxStaleAge))
                    && (cached.vical().notAfter() == null
                            || now.isBefore(cached.vical().notAfter()))) {
                LOG.warnf("VICAL refresh from %s failed, using the cached list: %s", url, e.getMessage());
                return cached.vical();
            }
            throw new IllegalStateException("VICAL could not be loaded from " + url + ": " + e.getMessage(), e);
        }
    }

    byte[] fetch() throws Exception {
        if (session == null) throw new IllegalStateException("No KeycloakSession available for HTTP requests");
        HttpGet get = new HttpGet(url);
        get.setHeader("Accept", "application/cbor, application/octet-stream");
        try (CloseableHttpResponse response =
                session.getProvider(HttpClientProvider.class).getHttpClient().execute(get)) {
            int status = response.getStatusLine().getStatusCode();
            if (status != 200) throw new IllegalStateException("HTTP " + status);
            HttpEntity entity = response.getEntity();
            if (entity == null) throw new IllegalStateException("empty response");
            try (InputStream in = entity.getContent()) {
                byte[] body = in.readNBytes(MAX_VICAL_BYTES + 1);
                if (body.length > MAX_VICAL_BYTES)
                    throw new IllegalStateException("VICAL exceeds " + MAX_VICAL_BYTES + " bytes");
                return body;
            }
        }
    }

    /** Verifies and reads a signed VICAL. */
    static Vical parse(byte[] signedVical, List<X509Certificate> signingCertificates, Instant now) throws Exception {
        if (signingCertificates.isEmpty()) {
            throw new IllegalStateException("No VICAL signing certificate configured");
        }
        CBORItem item = new CBORDecoder(signedVical).next();
        if (item instanceof CBORTaggedItem tagged && tagged.getTagNumber().intValue() == 18) {
            item = tagged.getTagContent();
        }
        COSESign1 sign1 = COSESign1.build(item);
        List<X509Certificate> chain = sign1.getUnprotectedHeader() != null
                ? sign1.getUnprotectedHeader().getX5Chain()
                : null;
        if ((chain == null || chain.isEmpty()) && sign1.getProtectedHeader() != null) {
            chain = sign1.getProtectedHeader().getX5Chain();
        }
        if (chain == null || chain.isEmpty()) throw new IllegalStateException("VICAL has no x5chain");
        PublicKey signerKey = X5cChainValidator.validateCertChain(chain, signingCertificates);
        if (!new COSEVerifier(signerKey).verify(sign1)) {
            throw new IllegalStateException("VICAL signature does not verify");
        }
        if (!(sign1.getPayload() instanceof CBORByteArray payload)) {
            throw new IllegalStateException("VICAL has no payload");
        }
        if (!(new CBORDecoder(payload.getValue()).next() instanceof CBORPairList vical)) {
            throw new IllegalStateException("VICAL payload is not a map");
        }
        Instant notAfter = instant(field(vical, "notAfter"));
        if (notAfter != null && !now.isBefore(notAfter)) {
            throw new IllegalStateException("VICAL expired at " + notAfter);
        }
        if (!(field(vical, "certificateInfos") instanceof CBORItemList infos)) {
            throw new IllegalStateException("VICAL has no certificateInfos");
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<Entry> entries = new ArrayList<>();
        for (CBORItem info : infos.getItems()) {
            if (!(info instanceof CBORPairList certInfo)
                    || !(field(certInfo, "certificate") instanceof CBORByteArray der)
                    || !(field(certInfo, "docType") instanceof CBORItemList docTypeList)) {
                throw new IllegalStateException("Malformed VICAL certificateInfo");
            }
            X509Certificate certificate =
                    (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der.getValue()));
            List<String> docTypes = new ArrayList<>();
            for (CBORItem docType : docTypeList.getItems()) {
                if (docType instanceof CBORString text) docTypes.add(text.getValue());
            }
            entries.add(new Entry(certificate, List.copyOf(docTypes)));
        }
        return new Vical(List.copyOf(entries), instant(field(vical, "nextUpdate")), notAfter);
    }

    private static CBORItem field(CBORPairList map, String key) {
        for (CBORPair pair : map.getPairs()) {
            if (pair.getKey() instanceof CBORString name && key.equals(name.getValue())) return pair.getValue();
        }
        return null;
    }

    private static Instant instant(CBORItem item) {
        if (item instanceof CBORTaggedItem tagged) item = tagged.getTagContent();
        if (item instanceof CBORString text) {
            try {
                return Instant.parse(text.getValue());
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    /** Clears cached VICALs; for tests. */
    static void clearCache() {
        CACHE.clear();
    }
}
