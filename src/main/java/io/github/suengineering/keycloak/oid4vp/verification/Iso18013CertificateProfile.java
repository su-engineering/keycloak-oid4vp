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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Checks an mDoc issuer chain against the ISO/IEC 18013-5 Annex B certificate profiles, after the
 * chain itself has been validated:
 *
 * <ul>
 *   <li>the document signer (leaf) is an end-entity certificate with key usage
 *       {@code digitalSignature} and extended key usage {@code id-mdl-kp-mdlDS} (1.0.18013.5.1.2);
 *   <li>the IACA that anchors the chain is a CA certificate with key usage {@code keyCertSign};
 *   <li>the document signer and the IACA carry the same {@code countryName};
 *   <li>the MSO was signed while the document signer certificate was valid.
 * </ul>
 */
final class Iso18013CertificateProfile {

    static final String MDL_DS_EKU = "1.0.18013.5.1.2";
    private static final int DIGITAL_SIGNATURE = 0;
    private static final int KEY_CERT_SIGN = 5;

    private Iso18013CertificateProfile() {}

    static void check(List<X509Certificate> chain, List<X509Certificate> trustedCertificates, Instant msoSigned)
            throws Exception {
        X509Certificate signer = chain.get(0);
        if (signer.getBasicConstraints() >= 0) {
            throw new IllegalStateException("ISO 18013-5: the document signer must not be a CA certificate");
        }
        boolean[] keyUsage = signer.getKeyUsage();
        if (keyUsage == null || !keyUsage[DIGITAL_SIGNATURE]) {
            throw new IllegalStateException("ISO 18013-5: the document signer needs key usage digitalSignature");
        }
        List<String> extendedKeyUsage = signer.getExtendedKeyUsage();
        if (extendedKeyUsage == null || !extendedKeyUsage.contains(MDL_DS_EKU)) {
            throw new IllegalStateException("ISO 18013-5: the document signer needs extended key usage " + MDL_DS_EKU);
        }

        X509Certificate iaca = anchor(chain, trustedCertificates);
        boolean[] iacaKeyUsage = iaca.getKeyUsage();
        if (iaca.getBasicConstraints() < 0 || iacaKeyUsage == null || !iacaKeyUsage[KEY_CERT_SIGN]) {
            throw new IllegalStateException(
                    "ISO 18013-5: the IACA must be a CA certificate with key usage keyCertSign");
        }
        String signerCountry = country(signer);
        if (signerCountry == null || !signerCountry.equals(country(iaca))) {
            throw new IllegalStateException("ISO 18013-5: the document signer and IACA countryName must match");
        }

        if (msoSigned == null) {
            throw new IllegalStateException("ISO 18013-5: MSO validityInfo has no signed time");
        }
        if (msoSigned.isBefore(signer.getNotBefore().toInstant())
                || msoSigned.isAfter(signer.getNotAfter().toInstant())) {
            throw new IllegalStateException("ISO 18013-5: the MSO was signed outside the document signer validity");
        }
    }

    /** The trusted certificate the validated chain ends at: one contained in the chain, or the issuer of its top. */
    private static X509Certificate anchor(List<X509Certificate> chain, List<X509Certificate> trustedCertificates)
            throws Exception {
        for (int i = chain.size() - 1; i >= 1; i--) {
            for (X509Certificate trusted : trustedCertificates) {
                if (Arrays.equals(trusted.getEncoded(), chain.get(i).getEncoded())) return trusted;
            }
        }
        X509Certificate top = chain.get(chain.size() - 1);
        for (X509Certificate trusted : X5cChainValidator.currentlyValid(trustedCertificates)) {
            if (trusted.getBasicConstraints() < 0) continue;
            try {
                top.verify(trusted.getPublicKey());
                return trusted;
            } catch (Exception ignored) {
                // not this anchor
            }
        }
        throw new IllegalStateException("ISO 18013-5: the document signer is not issued by a trusted IACA");
    }

    private static String country(X509Certificate certificate) throws Exception {
        for (Rdn rdn : new LdapName(certificate.getSubjectX500Principal().getName()).getRdns()) {
            if ("C".equalsIgnoreCase(rdn.getType()))
                return rdn.getValue().toString().toUpperCase(java.util.Locale.ROOT);
        }
        return null;
    }
}
