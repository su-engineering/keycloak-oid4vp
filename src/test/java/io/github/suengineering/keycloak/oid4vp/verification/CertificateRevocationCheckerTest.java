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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.x500.X500Principal;
import org.apache.http.client.methods.HttpUriRequest;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertificateRevocationCheckerTest {

    private static final String OCSP_URL = "http://ocsp.example/";
    private static final String CRL_URL = "http://crl.example/ca.crl";

    private KeyPair caKeys;
    private X509Certificate ca;
    private KeyPair leafKeys;
    private X509Certificate leaf;
    private final Map<String, byte[]> served = new ConcurrentHashMap<>();

    @BeforeEach
    void setUp() throws Exception {
        CertificateRevocationChecker.clearCaches();
        served.clear();
        caKeys = p256();
        ca = certificate("CN=Issuing CA", caKeys, "CN=Issuing CA", caKeys, true, null, false);
        leafKeys = p256();
        leaf = certificate("CN=Credential Issuer", leafKeys, "CN=Issuing CA", caKeys, false, null, true);
    }

    @Test
    void ourOcspRequestIsValidDer() throws Exception {
        OCSPReq request = new OCSPReq(CertificateRevocationChecker.ocspRequest(leaf, ca));

        assertThat(request.getRequestList()).hasSize(1);
        CertificateID id = request.getRequestList()[0].getCertID();
        assertThat(id.getSerialNumber()).isEqualTo(leaf.getSerialNumber());
        assertThat(id.matchesIssuer(new JcaX509CertificateHolder(ca), digests()))
                .isTrue();
    }

    @Test
    void readsResponderAndDistributionPointUrls() {
        assertThat(CertificateRevocationChecker.ocspUrls(leaf)).containsExactly(OCSP_URL);
        assertThat(CertificateRevocationChecker.crlUrls(leaf)).containsExactly(CRL_URL);
    }

    @Test
    void goodOcspAnswerPasses() throws Exception {
        served.put(OCSP_URL, ocsp(CertificateStatus.GOOD, caKeys, ca, null));

        assertThatCode(() -> checker(CertificateRevocationChecker.Mode.STRICT).check(chain()))
                .doesNotThrowAnyException();
    }

    @Test
    void revokedOcspAnswerIsRejectedInEveryMode() throws Exception {
        served.put(OCSP_URL, ocsp(new RevokedStatus(new Date(), CRLReason.keyCompromise), caKeys, ca, null));

        assertThatThrownBy(() -> checker(CertificateRevocationChecker.Mode.SOFT).check(chain()))
                .hasMessageContaining("revoked");
    }

    @Test
    void ocspAnswerSignedByAStrangerIsIgnoredAndTheCrlDecides() throws Exception {
        KeyPair stranger = p256();
        X509Certificate strangerCert =
                certificate("CN=Stranger", stranger, "CN=Stranger", stranger, false, null, false);
        served.put(OCSP_URL, ocsp(CertificateStatus.GOOD, stranger, strangerCert, null));
        served.put(CRL_URL, crl(caKeys, leaf.getSerialNumber(), Instant.now().plus(1, ChronoUnit.DAYS)));

        assertThatThrownBy(() -> checker(CertificateRevocationChecker.Mode.SOFT).check(chain()))
                .hasMessageContaining("revoked");
    }

    @Test
    void delegatedResponderNeedsTheOcspSigningKeyPurpose() throws Exception {
        KeyPair responderKeys = p256();
        X509Certificate delegate = certificate(
                "CN=OCSP Responder",
                responderKeys,
                "CN=Issuing CA",
                caKeys,
                false,
                KeyPurposeId.id_kp_OCSPSigning,
                false);
        served.put(OCSP_URL, ocsp(CertificateStatus.GOOD, responderKeys, delegate, delegate));
        assertThatCode(() -> checker(CertificateRevocationChecker.Mode.STRICT).check(chain()))
                .doesNotThrowAnyException();

        CertificateRevocationChecker.clearCaches();
        X509Certificate notADelegate =
                certificate("CN=Not a responder", responderKeys, "CN=Issuing CA", caKeys, false, null, false);
        served.put(OCSP_URL, ocsp(CertificateStatus.GOOD, responderKeys, notADelegate, notADelegate));
        assertThatThrownBy(
                        () -> checker(CertificateRevocationChecker.Mode.STRICT).check(chain()))
                .hasMessageContaining("cannot be determined");
    }

    @Test
    void unknownStatusFallsBackToTheCrl() throws Exception {
        served.put(OCSP_URL, ocsp(new UnknownStatus(), caKeys, ca, null));
        served.put(CRL_URL, crl(caKeys, BigInteger.valueOf(42), Instant.now().plus(1, ChronoUnit.DAYS)));

        assertThatCode(() -> checker(CertificateRevocationChecker.Mode.STRICT).check(chain()))
                .doesNotThrowAnyException();
    }

    @Test
    void outdatedOrForeignCrlsDoNotCount() throws Exception {
        served.put(CRL_URL, crl(caKeys, BigInteger.valueOf(42), Instant.now().minus(1, ChronoUnit.HOURS)));
        assertThatThrownBy(
                        () -> checker(CertificateRevocationChecker.Mode.STRICT).check(chain()))
                .hasMessageContaining("cannot be determined");

        CertificateRevocationChecker.clearCaches();
        served.put(CRL_URL, crl(p256(), BigInteger.valueOf(42), Instant.now().plus(1, ChronoUnit.DAYS)));
        assertThatThrownBy(
                        () -> checker(CertificateRevocationChecker.Mode.STRICT).check(chain()))
                .hasMessageContaining("cannot be determined");
    }

    @Test
    void softModeAcceptsWhenNothingAnswers() throws Exception {
        assertThatCode(() -> checker(CertificateRevocationChecker.Mode.SOFT).check(chain()))
                .doesNotThrowAnyException();
        assertThatThrownBy(
                        () -> checker(CertificateRevocationChecker.Mode.STRICT).check(chain()))
                .hasMessageContaining("cannot be determined");
        assertThatCode(() -> CertificateRevocationChecker.DISABLED.check(chain()))
                .doesNotThrowAnyException();
    }

    @Test
    void trustAnchorsThemselvesAreNotChecked() throws Exception {
        // The leaf is pinned: nothing sits below the anchor.
        X5cChainValidator.AnchoredChain pinned = X5cChainValidator.anchorChain(List.of(leaf), List.of(leaf));

        assertThat(pinned.belowAnchor()).isEmpty();
        assertThatCode(() -> checker(CertificateRevocationChecker.Mode.STRICT).check(pinned))
                .doesNotThrowAnyException();
    }

    private X5cChainValidator.AnchoredChain chain() throws Exception {
        return X5cChainValidator.anchorChain(List.of(leaf), List.of(ca));
    }

    private CertificateRevocationChecker checker(CertificateRevocationChecker.Mode mode) {
        return new CertificateRevocationChecker(null, mode) {
            @Override
            byte[] fetch(HttpUriRequest request, int maxBytes) {
                byte[] body = served.get(request.getURI().toString());
                if (body == null) throw new IllegalStateException("HTTP 404");
                return body;
            }
        };
    }

    private byte[] ocsp(
            CertificateStatus status, KeyPair signerKeys, X509Certificate signer, X509Certificate includedCert)
            throws Exception {
        CertificateID id = new CertificateID(
                digests().get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(ca), leaf.getSerialNumber());
        BasicOCSPRespBuilder builder =
                new BasicOCSPRespBuilder(new RespID(new JcaX509CertificateHolder(signer).getSubject()));
        builder.addResponse(id, status, new Date(), Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        X509CertificateHolder[] chain =
                includedCert == null ? null : new X509CertificateHolder[] {new JcaX509CertificateHolder(includedCert)};
        var basic = builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(signerKeys.getPrivate()), chain, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    private byte[] crl(KeyPair signer, BigInteger revokedSerial, Instant nextUpdate) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                new JcaX509CertificateHolder(ca).getSubject(),
                Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));
        builder.setNextUpdate(Date.from(nextUpdate));
        builder.addCRLEntry(revokedSerial, new Date(), CRLReason.keyCompromise);
        return builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate()))
                .getEncoded();
    }

    private static org.bouncycastle.operator.DigestCalculatorProvider digests() throws Exception {
        return new JcaDigestCalculatorProviderBuilder().build();
    }

    private static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(
            String subject,
            KeyPair keys,
            String issuer,
            KeyPair issuerKeys,
            boolean ca,
            KeyPurposeId eku,
            boolean revocationPointers)
            throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuer),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(30, ChronoUnit.DAYS)),
                new X500Principal(subject),
                keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (eku != null) builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        if (revocationPointers) {
            builder.addExtension(
                    Extension.authorityInfoAccess,
                    false,
                    new AuthorityInformationAccess(new AccessDescription(
                            AccessDescription.id_ad_ocsp,
                            new GeneralName(GeneralName.uniformResourceIdentifier, OCSP_URL))));
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(
                        new DistributionPointName(
                                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, CRL_URL))),
                        null,
                        null)
            }));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
    }
}
