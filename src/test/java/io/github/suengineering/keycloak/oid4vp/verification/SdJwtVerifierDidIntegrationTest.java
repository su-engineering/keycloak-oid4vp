/*
 * Copyright 2026 Bundesagentur fuer Arbeit
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
import static org.mockito.Mockito.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.suengineering.keycloak.oid4vp.domain.SdJwtVerificationResult;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.util.KeyWrapperUtil;

class SdJwtVerifierDidIntegrationTest {

    private SdJwtVerifier verifier;
    private DidResolver didResolver;
    private ECKey didSigningKey;
    private ECKey x509SigningKey;
    private ECKey caKey;
    private java.security.cert.X509Certificate x509Cert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SdJwtVerifierDidIntegrationTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        didResolver = mock(DidResolver.class);
        verifier = new SdJwtVerifier(60, 300, didResolver);
        didSigningKey = new ECKeyGenerator(Curve.P_256).generate();
        x509SigningKey = new ECKeyGenerator(Curve.P_256).generate();
        caKey = new ECKeyGenerator(Curve.P_256).generate();
        x509Cert = generateSelfSignedCert(caKey);
    }

    @Nested
    class DidResolutionIntegration {

        @Test
        void verify_didWebIssuer_resolvesViaDidResolver() throws Exception {
            String issuer = "did:web:example.com";
            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), any())).thenAnswer(inv -> createVerifiers(didSigningKey));

            String sdJwt = buildSdJwtWithDidIssuer(issuer, didSigningKey);
            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo(issuer);
            assertThat(result.credentialType()).isEqualTo("TestCredential");
            assertThat(result.claims()).containsEntry("sub", "user123");
        }

        @Test
        void verify_didWebWithPathIssuer_resolvesViaDidResolver() throws Exception {
            String issuer = "did:web:example.com:path:to:issuer";
            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), any())).thenAnswer(inv -> createVerifiers(didSigningKey));

            String sdJwt = buildSdJwtWithDidIssuer(issuer, didSigningKey);
            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo(issuer);
        }

        @Test
        void verify_didWebSignatureVerificationSucceeds() throws Exception {
            String issuer = "did:web:issuer.example";
            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), any())).thenAnswer(inv -> createVerifiers(didSigningKey));

            String sdJwt = buildSdJwtWithDidIssuer(issuer, didSigningKey);
            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.claims()).containsEntry("testClaim", "testValue");
        }

        @Test
        void verify_didWebWithDisclosures_mergesClaimsCorrectly() throws Exception {
            String issuer = "did:web:issuer.example";
            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), any())).thenAnswer(inv -> createVerifiers(didSigningKey));

            String sdJwt = buildSdJwtWithDisclosures(issuer, didSigningKey);
            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.claims()).containsEntry("given_name", "ERIKA");
            assertThat(result.claims()).doesNotContainKey("_sd");
        }
    }

    @Nested
    class DidFailureAndX5cIsolation {

        @Test
        void verify_didFailureCannotBeBypassedWithValidX5c() throws Exception {
            var entityCert = generateCaSignedCert(x509SigningKey, caKey, x509Cert);
            for (String issuer : List.of("did:web:issuer.example", "did:webvh:QmExample:issuer.example")) {
                String presentation = buildSignedJwtWithX5c(
                                Map.of("iss", issuer, "vct", "Membership"),
                                x509SigningKey,
                                List.of(entityCert, x509Cert))
                        + "~";
                when(didResolver.supports(issuer)).thenReturn(false);
                assertThatThrownBy(() -> verifier.verify(presentation, null, null, List.of(x509Cert)))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("disabled or unsupported");
                when(didResolver.supports(issuer)).thenReturn(true);
                when(didResolver.resolve(eq(issuer), any())).thenReturn(List.of());
                assertThatThrownBy(() -> verifier.verify(presentation, null, null, List.of(x509Cert)))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("DID resolution failed");
                when(didResolver.resolve(eq(issuer), any())).thenThrow(new DidResolutionException("Invalid history"));
                assertThatThrownBy(() -> verifier.verify(presentation, null, null, List.of(x509Cert)))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("DID resolution failed");
                if (issuer.startsWith("did:webvh:")) {
                    assertThatThrownBy(() -> new SdJwtVerifier(60, 300, null)
                                    .verify(presentation, null, null, List.of(x509Cert)))
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("disabled or unsupported");
                }
            }
        }

        @Test
        void verify_x5cChainWithCaTrust_stillWorks() throws Exception {
            ECKey caKeyLocal = new ECKeyGenerator(Curve.P_256).generate();
            java.security.cert.X509Certificate caCert = generateSelfSignedCert(caKeyLocal, "CN=Test CA");

            ECKey entityKey = new ECKeyGenerator(Curve.P_256).generate();
            java.security.cert.X509Certificate entityCert = generateCaSignedCert(entityKey, caKeyLocal, caCert);

            String jwt = buildSignedJwtWithX5c(
                    Map.of("iss", "https://issuer.example", "vct", "PID"), entityKey, List.of(entityCert, caCert));
            String sdJwt = jwt + "~";

            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(caCert));

            assertThat(result.issuer()).isEqualTo("https://issuer.example");
            assertThat(result.credentialType()).isEqualTo("PID");
        }
    }

    @Nested
    class RegressionTests {

        @Test
        void verify_x509IssuerStillWorks() throws Exception {
            String sdJwt = buildSdJwtWithProperX5cChain();

            when(didResolver.supports(anyString())).thenReturn(false);

            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo("https://fallback-issuer.example");
        }

        @Test
        void verify_nullDidResolver_fallsBackToExistingBehavior() throws Exception {
            SdJwtVerifier verifierWithoutDid = new SdJwtVerifier(60, 300, null);

            String sdJwt = buildSdJwtWithProperX5cChain();
            SdJwtVerificationResult result = verifierWithoutDid.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo("https://fallback-issuer.example");
        }

        @Test
        void verify_didWebWithoutKid_usesFirstAvailableMethod() throws Exception {
            String issuer = "did:web:multi-key.issuer.com";
            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), eq(null))).thenAnswer(inv -> createVerifiers(didSigningKey));

            String sdJwt = buildSdJwtWithDidIssuerWithoutKid(issuer, didSigningKey);
            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo(issuer);
        }

        @Test
        void verify_expiredJwt_throwsViaDidResolution() throws Exception {
            String issuer = "did:web:expired-issuer.com";
            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), any())).thenAnswer(inv -> createVerifiers(didSigningKey));

            String sdJwt = buildExpiredSdJwtWithDidIssuer(issuer, didSigningKey);

            assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, List.of(x509Cert)))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void verify_invalidSignature_throws() throws Exception {
            String issuer = "did:web:wrong-key.issuer.com";
            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), any())).thenAnswer(inv -> createVerifiers(didSigningKey));

            ECKey wrongKey = new ECKeyGenerator(Curve.P_256).generate();
            String sdJwt = buildSdJwtWithDidIssuer(issuer, wrongKey);

            assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, List.of(x509Cert)))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    class KeyIdMatching {

        @Test
        void verify_didWebWithMatchingKid_usesCorrectKey() throws Exception {
            ECKey key1 = new ECKeyGenerator(Curve.P_256).generate();
            ECKey key2 = new ECKeyGenerator(Curve.P_256).generate();
            String keyId = "key-2";

            when(didResolver.supports("did:web:multi-key.example")).thenReturn(true);
            when(didResolver.resolve(eq("did:web:multi-key.example"), eq(keyId)))
                    .thenAnswer(inv -> createVerifiers(key2));

            String sdJwt = buildSdJwtWithDidIssuerAndKid("did:web:multi-key.example", key2, keyId);
            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo("did:web:multi-key.example");
        }

        @Test
        void verify_didWebWithDifferentKid_fallsBackToX5c() throws Exception {
            ECKey matchingKey = new ECKeyGenerator(Curve.P_256).generate();

            when(didResolver.supports("did:web:kid-test.example")).thenReturn(true);
            when(didResolver.resolve(eq("did:web:kid-test.example"), eq("wrong-key")))
                    .thenReturn(List.of());

            String sdJwt = buildSdJwtWithProperX5cChain();
            SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo("https://fallback-issuer.example");
        }

        @Test
        void verify_kbJwtStillWorksWithDidIssuer() throws Exception {
            ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
            String issuer = "did:web:kb-issuer.example";

            when(didResolver.supports(issuer)).thenReturn(true);
            when(didResolver.resolve(eq(issuer), any())).thenAnswer(inv -> createVerifiers(didSigningKey));

            String sdJwt =
                    buildSdJwtVpWithKbJwt(issuer, didSigningKey, holderKey, "https://verifier.example", "test-nonce");
            SdJwtVerificationResult result =
                    verifier.verify(sdJwt, "https://verifier.example", "test-nonce", List.of(x509Cert));

            assertThat(result.issuer()).isEqualTo(issuer);
            assertThat(result.claims()).containsKey("cnf");
        }
    }

    private List<SignatureVerifierContext> createVerifiers(ECKey key) throws Exception {
        return List.of(createVerifierContext(key.toECPublicKey()));
    }

    private SignatureVerifierContext createVerifierContext(java.security.PublicKey publicKey) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPublicKey(publicKey);
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setType(KeyType.EC);
        if (publicKey instanceof ECPublicKey ecKey) {
            keyWrapper.setCurve(resolveCurveName(ecKey));
        }
        return KeyWrapperUtil.createSignatureVerifierContext(keyWrapper);
    }

    private String resolveCurveName(ECPublicKey publicKey) {
        int fieldSize = publicKey.getParams().getCurve().getField().getFieldSize();
        return switch (fieldSize) {
            case 256 -> "P-256";
            case 384 -> "P-384";
            case 521 -> "P-521";
            default -> throw new IllegalStateException("Unsupported EC curve field size: " + fieldSize);
        };
    }

    private String buildSdJwtWithDidIssuer(String issuer, ECKey signingKey) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vct", "TestCredential")
                .claim("sub", "user123")
                .claim("testClaim", "testValue")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize() + "~";
    }

    private String buildSdJwtWithDidIssuerWithoutKid(String issuer, ECKey signingKey) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vct", "TestCredential")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize() + "~";
    }

    private String buildSdJwtWithDidIssuerAndKid(String issuer, ECKey signingKey, String keyId) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vct", "TestCredential")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize() + "~";
    }

    private String buildExpiredSdJwtWithDidIssuer(String issuer, ECKey signingKey) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vct", "TestCredential")
                .issueTime(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)))
                .expirationTime(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize() + "~";
    }

    private String buildSdJwtWithProperX5cChain() throws Exception {
        ECKey entityKey = new ECKeyGenerator(Curve.P_256).generate();
        java.security.cert.X509Certificate entityCert = generateCaSignedCert(entityKey, caKey, x509Cert);

        String jwt = buildSignedJwtWithX5c(
                Map.of("iss", "https://fallback-issuer.example", "vct", "FallbackCredential"),
                entityKey,
                List.of(entityCert, x509Cert));
        return jwt + "~";
    }

    private String buildSdJwtWithX5c(ECKey signingKey, java.security.cert.X509Certificate cert) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://fallback-issuer.example")
                .claim("vct", "FallbackCredential")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize() + "~";
    }

    private String buildSignedJwtWithX5c(
            Map<String, Object> claimsMap, ECKey key, List<java.security.cert.X509Certificate> x5cCerts)
            throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        Instant now = Instant.now();
        builder.issueTime(Date.from(now));
        builder.expirationTime(Date.from(now.plus(86400, ChronoUnit.SECONDS)));

        List<Base64> x5cB64 = x5cCerts.stream()
                .map(c -> {
                    try {
                        return Base64.encode(c.getEncoded());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .toList();

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).x509CertChain(x5cB64).build();
        SignedJWT signedJWT = new SignedJWT(header, builder.build());
        signedJWT.sign(new ECDSASigner(key));
        return signedJWT.serialize();
    }

    private String buildSdJwtWithDisclosures(String issuer, ECKey signingKey) throws Exception {
        String disclosureJson = "[\"salt123\",\"given_name\",\"ERIKA\"]";
        String disclosureB64 = Base64URL.encode(disclosureJson.getBytes(StandardCharsets.UTF_8))
                .toString();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(disclosureB64.getBytes(StandardCharsets.US_ASCII));
        String digest = Base64URL.encode(hash).toString();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vct", "TestCredential")
                .claim("_sd", List.of(digest))
                .claim("_sd_alg", "sha-256")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize() + "~" + disclosureB64 + "~";
    }

    private String buildSdJwtVpWithKbJwt(String issuer, ECKey issuerKey, ECKey holderKey, String audience, String nonce)
            throws Exception {
        JWTClaimsSet credClaims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vct", "TestCredential")
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .build();

        SignedJWT credJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), credClaims);
        credJwt.sign(new ECDSASigner(issuerKey));
        String unboundPresentation = credJwt.serialize() + "~";

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(unboundPresentation.getBytes(StandardCharsets.US_ASCII));
        String sdHash = Base64URL.encode(hash).toString();

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience(audience)
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .issueTime(Date.from(Instant.now()))
                .build();

        SignedJWT kbJwt = new SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new com.nimbusds.jose.JOSEObjectType("kb+jwt"))
                        .build(),
                kbClaims);
        kbJwt.sign(new ECDSASigner(holderKey));

        return unboundPresentation + kbJwt.serialize();
    }

    private static java.security.cert.X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
        return generateSelfSignedCert(ecKey, "CN=Test CA");
    }

    private static java.security.cert.X509Certificate generateSelfSignedCert(ECKey ecKey, String dn) throws Exception {
        ECPublicKey publicKey = ecKey.toECPublicKey();
        X500Principal subject = new X500Principal(dn);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                publicKey);
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(ecKey.toECPrivateKey());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    private static java.security.cert.X509Certificate generateCaSignedCert(
            ECKey subjectKey, ECKey caKey, java.security.cert.X509Certificate caCert) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caCert.getSubjectX500Principal(),
                BigInteger.valueOf(System.currentTimeMillis() + 1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Principal("CN=End Entity"),
                subjectKey.toECPublicKey());
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.toECPrivateKey());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
