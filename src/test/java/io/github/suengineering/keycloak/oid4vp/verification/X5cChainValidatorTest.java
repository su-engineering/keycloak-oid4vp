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

import static org.assertj.core.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class X5cChainValidatorTest {

    private KeyPair caKeyPair;
    private X509Certificate caCert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(X5cChainValidatorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        caKeyPair = generateKeyPair();
        caCert = generateCert(
                caKeyPair,
                caKeyPair,
                "CN=Test CA",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(365, ChronoUnit.DAYS),
                true);
    }

    @Test
    void validateCertChain_validChain_returnsLeafKey() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                caKeyPair,
                "CN=Leaf",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        PublicKey result = X5cChainValidator.validateCertChain(List.of(leafCert, caCert), List.of(caCert));
        assertThat(result).isEqualTo(leafCert.getPublicKey());
    }

    @Test
    void validateCertChain_expiredLeafCert_throws() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate expiredLeaf = generateCert(
                leafKp,
                caKeyPair,
                "CN=Expired Leaf",
                "CN=Test CA",
                Instant.now().minus(2, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.HOURS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(expiredLeaf, caCert), List.of(caCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired")
                .hasMessageContaining("position 0");
    }

    @Test
    void validateCertChain_notYetValidLeafCert_throws() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate futureLeaf = generateCert(
                leafKp,
                caKeyPair,
                "CN=Future Leaf",
                "CN=Test CA",
                Instant.now().plus(1, ChronoUnit.DAYS),
                Instant.now().plus(2, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(futureLeaf, caCert), List.of(caCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not yet valid")
                .hasMessageContaining("position 0");
    }

    @Test
    void validateCertChain_expiredIntermediateCert_throws() throws Exception {
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate expiredIntermediate = generateCert(
                intermediateKp,
                caKeyPair,
                "CN=Expired Intermediate",
                "CN=Test CA",
                Instant.now().minus(2, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.HOURS),
                true);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                intermediateKp,
                "CN=Leaf",
                "CN=Expired Intermediate",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() ->
                        X5cChainValidator.validateCertChain(List.of(leafCert, expiredIntermediate), List.of(caCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired")
                .hasMessageContaining("position 1");
    }

    @Test
    void validateCertChain_chainIncludingTrustedIntermediate_isAnchoredThere() throws Exception {
        // Trust list names an issuing CA whose own root is not trusted; the issuer sends that CA in x5c.
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate intermediate = generateCert(
                intermediateKp,
                caKeyPair,
                "CN=PID CA",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(30, ChronoUnit.DAYS),
                true);
        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                intermediateKp,
                "CN=PID Provider",
                "CN=PID CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThat(X5cChainValidator.validateCertChain(List.of(leafCert, intermediate), List.of(intermediate)))
                .isEqualTo(leafCert.getPublicKey());
    }

    @Test
    void validateCertChain_chainEndingAtUntrustedCa_isRejected() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                caKeyPair,
                "CN=Leaf",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);
        KeyPair otherKp = generateKeyPair();
        X509Certificate unrelatedRoot = generateCert(
                otherKp,
                otherKp,
                "CN=Other Root",
                "CN=Other Root",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                true);

        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(leafCert, caCert), List.of(unrelatedRoot)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not anchored");
    }

    @Test
    void validateCertChain_emptyChain_throws() {
        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(), List.of(caCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Empty x5c chain");
    }

    @Test
    void validateCertChain_untrustedChain_throws() throws Exception {
        KeyPair untrustedKp = generateKeyPair();
        X509Certificate untrustedCert = generateCert(
                untrustedKp,
                untrustedKp,
                "CN=Untrusted",
                "CN=Untrusted",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(untrustedCert), List.of(caCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not anchored");
    }

    @Test
    void validateCertChain_selfSignedLeaf_trustedDirectly_succeeds() throws Exception {
        PublicKey result = X5cChainValidator.validateCertChain(List.of(caCert), List.of(caCert));
        assertThat(result).isEqualTo(caCert.getPublicKey());
    }

    @Test
    void validateCertChain_nonCaIntermediate_throws() throws Exception {
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate nonCaIntermediate = generateCert(
                intermediateKp,
                caKeyPair,
                "CN=Intermediate",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                intermediateKp,
                "CN=Leaf",
                "CN=Intermediate",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() ->
                        X5cChainValidator.validateCertChain(List.of(leafCert, nonCaIntermediate), List.of(caCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not a CA certificate");
    }

    @Test
    void validateCertChain_expiredTrustAnchor_doesNotAnchor() throws Exception {
        X509Certificate expiredCa = generateCert(
                caKeyPair,
                caKeyPair,
                "CN=Test CA",
                "CN=Test CA",
                Instant.now().minus(10, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.DAYS),
                true);
        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                caKeyPair,
                "CN=Leaf",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(leafCert), List.of(expiredCa)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not anchored");
    }

    @Test
    void validateCertChain_nonCaTrustedCertificate_cannotIssueOtherCertificates() throws Exception {
        KeyPair trustedEndEntityKp = generateKeyPair();
        X509Certificate trustedEndEntity = generateCert(
                trustedEndEntityKp,
                trustedEndEntityKp,
                "CN=Trusted End Entity",
                "CN=Trusted End Entity",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);
        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                trustedEndEntityKp,
                "CN=Leaf",
                "CN=Trusted End Entity",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(leafCert), List.of(trustedEndEntity)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not anchored");
        assertThat(X5cChainValidator.validateCertChain(List.of(trustedEndEntity), List.of(trustedEndEntity)))
                .isEqualTo(trustedEndEntity.getPublicKey());
    }

    @Test
    void verifyJwtSignature_invalidX5c_isNotRetriedAgainstTrustedKeys() throws Exception {
        KeyPair otherKp = generateKeyPair();
        X509Certificate untrusted = generateCert(
                otherKp,
                otherKp,
                "CN=Untrusted",
                "CN=Untrusted",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);
        // Signed with the trusted CA key, but presenting a chain that does not validate.
        com.nimbusds.jose.JWSObject jws = new com.nimbusds.jose.JWSObject(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(untrusted.getEncoded())))
                        .build(),
                new com.nimbusds.jose.Payload("{\"sub\":\"x\"}"));
        jws.sign(new com.nimbusds.jose.crypto.ECDSASigner(
                (java.security.interfaces.ECPrivateKey) caKeyPair.getPrivate()));

        assertThatThrownBy(() -> X5cChainValidator.verifyJwtSignature(jws.serialize(), List.of(caCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("x5c chain validation failed");
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKp,
            KeyPair issuerKp,
            String subjectDn,
            String issuerDn,
            Instant notBefore,
            Instant notAfter,
            boolean isCa)
            throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(Instant.now().toEpochMilli()),
                Date.from(notBefore),
                Date.from(notAfter),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    void validateCertChain_enforcesPathLengthAndNameChaining() throws Exception {
        // caCert has no path length limit here, so build a pathLen-0 CA with an intermediate below it.
        KeyPair rootKp = generateKeyPair();
        var rootBuilder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=Root"),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(1, ChronoUnit.HOURS)),
                Date.from(Instant.now().plus(30, ChronoUnit.DAYS)),
                new X500Principal("CN=Root"),
                rootKp.getPublic());
        rootBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        X509Certificate root = new JcaX509CertificateConverter()
                .getCertificate(
                        rootBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKp.getPrivate())));
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate intermediate = generateCert(
                intermediateKp,
                rootKp,
                "CN=Intermediate",
                "CN=Root",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(10, ChronoUnit.DAYS),
                true);
        KeyPair leafKp = generateKeyPair();
        X509Certificate leaf = generateCert(
                leafKp,
                intermediateKp,
                "CN=Leaf",
                "CN=Intermediate",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(leaf, intermediate), List.of(root)))
                .hasMessageContaining("path length");

        X509Certificate misnamed = generateCert(
                leafKp,
                caKeyPair,
                "CN=Leaf",
                "CN=Someone Else",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);
        assertThatThrownBy(() -> X5cChainValidator.validateCertChain(List.of(misnamed, caCert), List.of(caCert)))
                .hasMessageContaining("do not link");
    }
}
