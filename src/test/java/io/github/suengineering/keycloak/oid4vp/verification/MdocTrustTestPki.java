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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A small IACA and document-signer PKI for mDoc trust tests. */
final class MdocTrustTestPki {

    final KeyPair iacaKeys;
    final X509Certificate iaca;

    MdocTrustTestPki(String country) throws Exception {
        this(country, true);
    }

    MdocTrustTestPki(String country, boolean keyCertSign) throws Exception {
        iacaKeys = p256();
        iaca = certificate(
                "C=" + country + ",CN=Test IACA " + country,
                iacaKeys,
                "C=" + country + ",CN=Test IACA " + country,
                iacaKeys,
                true,
                keyCertSign ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.cRLSign,
                false,
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(3650, ChronoUnit.DAYS));
    }

    /** A document signer issued by this IACA. */
    DocumentSigner documentSigner(String country, boolean mdlEku, Instant notBefore, Instant notAfter)
            throws Exception {
        KeyPair keys = p256();
        X509Certificate cert = certificate(
                "C=" + country + ",CN=Test Document Signer",
                keys,
                iaca.getSubjectX500Principal().getName(),
                iacaKeys,
                false,
                KeyUsage.digitalSignature,
                mdlEku,
                notBefore,
                notAfter);
        return new DocumentSigner(keys, cert);
    }

    DocumentSigner documentSigner(String country, boolean mdlEku) throws Exception {
        return documentSigner(
                country,
                mdlEku,
                Instant.now().minus(2, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
    }

    record DocumentSigner(KeyPair keys, X509Certificate certificate) {}

    static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    static X509Certificate certificate(
            String subject,
            KeyPair subjectKeys,
            String issuer,
            KeyPair issuerKeys,
            boolean ca,
            int keyUsage,
            boolean mdlEku,
            Instant notBefore,
            Instant notAfter)
            throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuer),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore),
                Date.from(notAfter),
                new X500Principal(subject),
                subjectKeys.getPublic());
        builder.addExtension(
                Extension.basicConstraints, true, ca ? new BasicConstraints(0) : new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        if (mdlEku) {
            builder.addExtension(
                    Extension.extendedKeyUsage,
                    true,
                    new ExtendedKeyUsage(
                            KeyPurposeId.getInstance(new ASN1ObjectIdentifier(Iso18013CertificateProfile.MDL_DS_EKU))));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
    }
}
