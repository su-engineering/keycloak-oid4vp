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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import com.authlete.cose.SigStructureBuilder;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class VicalProviderTest {

    private static final String MDL = "org.iso.18013.5.1.mDL";

    private KeyPair vicalSignerKeys;
    private X509Certificate vicalSigner;
    private MdocTrustTestPki us;
    private MdocTrustTestPki nl;

    @BeforeEach
    void setUp() throws Exception {
        VicalProvider.clearCache();
        vicalSignerKeys = MdocTrustTestPki.p256();
        vicalSigner = MdocTrustTestPki.certificate(
                "CN=VICAL Signer",
                vicalSignerKeys,
                "CN=VICAL Signer",
                vicalSignerKeys,
                false,
                KeyUsage.digitalSignature,
                false,
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(30, ChronoUnit.DAYS));
        us = new MdocTrustTestPki("US");
        nl = new MdocTrustTestPki("NL");
    }

    @AfterEach
    void tearDown() {
        VicalProvider.clearCache();
    }

    @Test
    void iacasOnlyAnchorTheDocTypesTheyAreListedFor() throws Exception {
        byte[] vical = signedVical(
                vicalSignerKeys, vicalSigner, null, entry(us.iaca, MDL), entry(nl.iaca, "org.example.other"));
        VicalProvider provider = provider(new AtomicReference<>(vical), new AtomicInteger());

        assertThat(provider.anchorsFor(MDL)).containsExactly(us.iaca);
        assertThat(provider.anchorsFor("org.example.other")).containsExactly(nl.iaca);
        assertThat(provider.anchorsFor("eu.europa.ec.eudi.pid.1")).isEmpty();
    }

    @Test
    void vicalSignedByAnotherKeyIsRejected() throws Exception {
        KeyPair otherKeys = MdocTrustTestPki.p256();
        X509Certificate other = MdocTrustTestPki.certificate(
                "CN=Someone Else",
                otherKeys,
                "CN=Someone Else",
                otherKeys,
                false,
                KeyUsage.digitalSignature,
                false,
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(30, ChronoUnit.DAYS));
        byte[] vical = signedVical(otherKeys, other, null, entry(us.iaca, MDL));

        assertThatThrownBy(() -> VicalProvider.parse(vical, List.of(vicalSigner), Instant.now()))
                .hasMessageContaining("not anchored");
    }

    @Test
    void tamperedVicalIsRejected() throws Exception {
        byte[] vical = signedVical(vicalSignerKeys, vicalSigner, null, entry(us.iaca, MDL));
        vical[vical.length - 10] ^= 0x01;

        assertThatThrownBy(() -> VicalProvider.parse(vical, List.of(vicalSigner), Instant.now()))
                .isInstanceOf(Exception.class);
    }

    @Test
    void expiredVicalIsRejected() throws Exception {
        byte[] vical = signedVical(
                vicalSignerKeys, vicalSigner, Instant.now().minus(1, ChronoUnit.HOURS), entry(us.iaca, MDL));

        assertThatThrownBy(() -> VicalProvider.parse(vical, List.of(vicalSigner), Instant.now()))
                .hasMessageContaining("expired");
    }

    @Test
    void withoutASigningCertificateNothingIsTrusted() throws Exception {
        byte[] vical = signedVical(vicalSignerKeys, vicalSigner, null, entry(us.iaca, MDL));

        assertThatThrownBy(() -> VicalProvider.parse(vical, List.of(), Instant.now()))
                .hasMessageContaining("No VICAL signing certificate");
    }

    @Test
    void cachedListIsUsedWhileARefreshFailsWithinTheStaleWindow() throws Exception {
        AtomicReference<byte[]> served =
                new AtomicReference<>(signedVical(vicalSignerKeys, vicalSigner, null, entry(us.iaca, MDL)));
        AtomicInteger fetches = new AtomicInteger();
        MutableClock clock = new MutableClock(Instant.now());
        VicalProvider provider =
                new VicalProvider(
                        null,
                        "https://vical.example/" + System.nanoTime(),
                        List.of(vicalSigner),
                        Duration.ofDays(2),
                        clock) {
                    @Override
                    byte[] fetch() {
                        fetches.incrementAndGet();
                        byte[] body = served.get();
                        if (body == null) throw new IllegalStateException("down");
                        return body;
                    }
                };

        assertThat(provider.anchorsFor(MDL)).containsExactly(us.iaca);
        served.set(null);
        clock.advance(Duration.ofHours(25));
        assertThat(provider.anchorsFor(MDL)).containsExactly(us.iaca);
        clock.advance(Duration.ofDays(2));
        assertThatThrownBy(() -> provider.anchorsFor(MDL)).hasMessageContaining("could not be loaded");
        assertThat(fetches.get()).isEqualTo(3);
    }

    @Test
    void vicalAnchorsLetAnMdlVerify() throws Exception {
        MdocTrustTestPki.DocumentSigner signer = us.documentSigner("US", true);
        MdocDeviceResponseTestHelper wallet =
                new MdocDeviceResponseTestHelper(signer.keys(), List.of(signer.certificate()));
        var transcript = MdocSessionTranscriptBuilder.buildOid4vp("client", "nonce", "https://rp/response", null);
        String token = wallet.build(transcript);
        VicalProvider provider = provider(
                new AtomicReference<>(signedVical(vicalSignerKeys, vicalSigner, null, entry(us.iaca, MDL))),
                new AtomicInteger());

        MdocVerifier verifier = new MdocVerifier();
        List<X509Certificate> anchors = provider.anchorsFor(verifier.signedDocType(token));

        assertThat(verifier.verifyWithTrustedCerts(
                        token, anchors, "client", "nonce", "https://rp/response", null, null))
                .isNotNull();
    }

    @Test
    void processorAddsVicalAnchorsAndSurvivesAVicalOutage() throws Exception {
        MdocTrustTestPki.DocumentSigner signer = us.documentSigner("US", true);
        MdocDeviceResponseTestHelper wallet =
                new MdocDeviceResponseTestHelper(signer.keys(), List.of(signer.certificate()));
        String query = "{\"credentials\":[{\"id\":\"mdl\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"" + MDL
                + "\"},\"claims\":[{\"path\":[\"org.iso.18013.5.1\",\"given_name\"]}]}]}";
        var transcript = MdocSessionTranscriptBuilder.buildOid4vp("client", "nonce", "https://rp/response", null);
        String token = wallet.build(transcript);
        var request = new VpTokenProcessor.Request(token, "client", "nonce", "https://rp/response", null, null, query);
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        // Only the VICAL knows this IACA; the trust list holds an unrelated anchor.
        TrustListProvider trustList = new TrustListProvider(List.of(nl.iaca));

        AtomicReference<byte[]> served =
                new AtomicReference<>(signedVical(vicalSignerKeys, vicalSigner, null, entry(us.iaca, MDL)));
        VpTokenProcessor withVical = new VpTokenProcessor(
                mapper, new StatusListVerifier(), trustList, provider(served, new AtomicInteger()));
        assertThat(withVical.process(request).getPrimaryCredential().credentialType())
                .isEqualTo(MDL);

        VicalProvider down =
                new VicalProvider(null, "https://vical.example/down", List.of(vicalSigner), Duration.ZERO) {
                    @Override
                    byte[] fetch() {
                        throw new IllegalStateException("down");
                    }
                };
        VpTokenProcessor vicalDown = new VpTokenProcessor(mapper, new StatusListVerifier(), trustList, down);
        assertThatThrownBy(() -> vicalDown.process(request)).hasMessageContaining("not anchored");
    }

    private VicalProvider provider(AtomicReference<byte[]> served, AtomicInteger fetches) {
        return new VicalProvider(
                null, "https://vical.example/" + System.nanoTime(), List.of(vicalSigner), Duration.ZERO) {
            @Override
            byte[] fetch() {
                fetches.incrementAndGet();
                return served.get();
            }
        };
    }

    private static CBORPairList entry(X509Certificate certificate, String docType) throws Exception {
        return new CBORPairList(List.of(
                new CBORPair(new CBORString("certificate"), new CBORByteArray(certificate.getEncoded())),
                new CBORPair(
                        new CBORString("serialNumber"),
                        new CBORByteArray(certificate.getSerialNumber().toByteArray())),
                new CBORPair(new CBORString("docType"), new CBORItemList(new CBORString(docType)))));
    }

    private static byte[] signedVical(
            KeyPair signerKeys, X509Certificate signer, Instant notAfter, CBORPairList... entries) throws Exception {
        List<CBORPair> fields = new ArrayList<>(List.of(
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString("vicalProvider"), new CBORString("Test VICAL Provider")),
                new CBORPair(
                        new CBORString("date"),
                        new CBORTaggedItem(
                                0,
                                new CBORString(Instant.now()
                                        .truncatedTo(ChronoUnit.SECONDS)
                                        .toString()))),
                new CBORPair(new CBORString("certificateInfos"), new CBORItemList(List.<CBORItem>of(entries)))));
        if (notAfter != null) {
            fields.add(new CBORPair(
                    new CBORString("notAfter"),
                    new CBORTaggedItem(
                            0,
                            new CBORString(
                                    notAfter.truncatedTo(ChronoUnit.SECONDS).toString()))));
        }
        byte[] payload = new CBORPairList(fields).encode();
        var protectedHeader = new COSEProtectedHeaderBuilder().alg(-7).build();
        var unprotectedHeader =
                new COSEUnprotectedHeaderBuilder().x5chain(List.of(signer)).build();
        var sigStructure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload)
                .build();
        byte[] signature = new COSESigner(signerKeys.getPrivate()).sign(sigStructure, -7);
        return new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotectedHeader)
                .payload(payload)
                .signature(signature)
                .build()
                .encode();
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
