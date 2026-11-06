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

import io.github.suengineering.keycloak.oid4vp.domain.MdocCertificateProfile;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;

class MdocCertificateProfileTest {

    private static final String NONCE = "nonce-1";
    private static final String CLIENT_ID = "x509_hash:abc";
    private static final String RESPONSE_URI = "https://verifier.example/response";

    private final MdocVerifier strict = new MdocVerifier(MdocCertificateProfile.ISO_18013_5);

    @Test
    void conformingChainPasses() throws Exception {
        MdocTrustTestPki pki = new MdocTrustTestPki("US");
        MdocTrustTestPki.DocumentSigner signer = pki.documentSigner("US", true);

        assertThat(verify(strict, pki, signer, List.of(signer.certificate())).docType())
                .isEqualTo("org.iso.18013.5.1.mDL");
    }

    @Test
    void chainThatAlsoCarriesTheIacaPasses() throws Exception {
        MdocTrustTestPki pki = new MdocTrustTestPki("US");
        MdocTrustTestPki.DocumentSigner signer = pki.documentSigner("US", true);

        assertThat(verify(strict, pki, signer, List.of(signer.certificate(), pki.iaca)))
                .isNotNull();
    }

    @Test
    void signerWithoutTheMdlExtendedKeyUsageIsRejected() throws Exception {
        MdocTrustTestPki pki = new MdocTrustTestPki("US");
        MdocTrustTestPki.DocumentSigner signer = pki.documentSigner("US", false);

        assertThatThrownBy(() -> verify(strict, pki, signer, List.of(signer.certificate())))
                .hasMessageContaining("1.0.18013.5.1.2");
        // Without the profile the same chain is fine: PID providers often use other profiles.
        assertThat(verify(new MdocVerifier(), pki, signer, List.of(signer.certificate())))
                .isNotNull();
    }

    @Test
    void countryMismatchIsRejected() throws Exception {
        MdocTrustTestPki pki = new MdocTrustTestPki("US");
        MdocTrustTestPki.DocumentSigner signer = pki.documentSigner("NL", true);

        assertThatThrownBy(() -> verify(strict, pki, signer, List.of(signer.certificate())))
                .hasMessageContaining("countryName");
    }

    @Test
    void iacaWithoutKeyCertSignIsRejected() throws Exception {
        MdocTrustTestPki pki = new MdocTrustTestPki("US", false);
        MdocTrustTestPki.DocumentSigner signer = pki.documentSigner("US", true);

        assertThatThrownBy(() -> verify(strict, pki, signer, List.of(signer.certificate())))
                .hasMessageContaining("keyCertSign");
    }

    @Test
    void msoSignedBeforeTheSignerWasValidIsRejected() throws Exception {
        MdocTrustTestPki pki = new MdocTrustTestPki("US");
        // The helper signs the MSO one hour ago; this signer only became valid ten minutes ago.
        MdocTrustTestPki.DocumentSigner signer = pki.documentSigner(
                "US",
                true,
                Instant.now().minus(10, ChronoUnit.MINUTES),
                Instant.now().plus(30, ChronoUnit.DAYS));

        assertThatThrownBy(() -> verify(strict, pki, signer, List.of(signer.certificate())))
                .hasMessageContaining("signed outside");
    }

    private static io.github.suengineering.keycloak.oid4vp.domain.MdocVerificationResult verify(
            MdocVerifier verifier,
            MdocTrustTestPki pki,
            MdocTrustTestPki.DocumentSigner signer,
            List<X509Certificate> x5chain)
            throws Exception {
        MdocDeviceResponseTestHelper wallet = new MdocDeviceResponseTestHelper(signer.keys(), x5chain);
        var transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
        return verifier.verifyWithTrustedCerts(
                wallet.build(transcript), List.of(pki.iaca), CLIENT_ID, NONCE, RESPONSE_URI, null, null);
    }
}
