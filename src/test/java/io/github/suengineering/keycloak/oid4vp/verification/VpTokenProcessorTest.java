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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
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
import io.github.suengineering.keycloak.oid4vp.domain.PresentationType;
import io.github.suengineering.keycloak.oid4vp.domain.VerifiedCredential;
import io.github.suengineering.keycloak.oid4vp.domain.VpTokenResult;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.crypto.CryptoIntegration;

class VpTokenProcessorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private VpTokenProcessor processor;
    private ECKey signingKey;
    private ECKey holderKey;
    private X509Certificate signingCert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(VpTokenProcessorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        holderKey = new ECKeyGenerator(Curve.P_256).generate();
        signingCert = generateSelfSignedCert(signingKey);
        TrustListProvider trustListProvider = new TrustListProvider(List.of(signingCert));
        processor = new VpTokenProcessor(objectMapper, new StatusListVerifier(), trustListProvider);
    }

    @Test
    void process_singleSdJwt_returnsResult() throws Exception {
        String credJwt = buildSdJwt(Map.of(
                "iss",
                "https://issuer.example",
                "vct",
                "IdentityCredential",
                "sub",
                "user1",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));
        String sdJwt = buildSdJwtVpWithKbJwt(credJwt, "client-id", "nonce");

        VpTokenResult result = processor.process(request(sdJwt, "client-id", "nonce", null));

        assertThat(result.credentials()).hasSize(1);
        VerifiedCredential primary = result.getPrimaryCredential();
        assertThat(primary.presentationType()).isEqualTo(PresentationType.SD_JWT);
        assertThat(primary.issuer()).isEqualTo("https://issuer.example");
        assertThat(primary.credentialType()).isEqualTo("IdentityCredential");
        assertThat(result.getPrimaryCredential().claims()).containsEntry("sub", "user1");
    }

    @Test
    void multipleCredentialTypesKeepAllClaimsInRequestOrder() throws Exception {
        String membership = presentation("Membership", "Alice", "nonce");
        String license = presentation("License", "Bob", "nonce");
        String query = query("Membership", "License");
        // Wallet order must not choose the login identity; duplicate claim names must not be merged.
        String wrapper = objectMapper.writeValueAsString(
                new LinkedHashMap<>(Map.of("cred2", List.of(license), "cred1", List.of(membership))));
        VpTokenResult result = processor.process(dcqlRequest(wrapper, query));
        assertThat(result.credentials().keySet()).containsExactly("cred1", "cred2");
        assertThat(result.getPrimaryCredential().claims()).containsEntry("sub", "Alice");
        assertThat(result.credentials().get("cred2").get(0).claims()).containsEntry("sub", "Bob");
    }

    @Test
    void repeatedQueryKeepsEveryPresentationWhenMultipleIsEnabled() throws Exception {
        String wrapper = objectMapper.writeValueAsString(Map.of(
                "cred1",
                List.of(presentation("Membership", "Alice", "nonce"), presentation("Membership", "Bob", "nonce"))));
        String query = query("Membership");
        assertThatThrownBy(() -> processor.process(dcqlRequest(wrapper, query)))
                .hasMessageContaining("Multiple presentations are not allowed");
        var result =
                processor.process(dcqlRequest(wrapper, query.replace("\"format\"", "\"multiple\":true,\"format\"")));
        assertThat(result.credentials().get("cred1")).hasSize(2);
    }

    @Test
    void missingRequiredCredentialAndSwappedQueryIdsAreRejected() throws Exception {
        String member = presentation("Membership", "Alice", "nonce");
        String license = presentation("License", "Alice", "nonce");
        String query = query("Membership", "License");
        assertThatThrownBy(() -> processor.process(
                        dcqlRequest(objectMapper.writeValueAsString(Map.of("cred1", List.of(member))), query)))
                .hasMessageContaining("Missing required");
        assertThatThrownBy(() -> processor.process(dcqlRequest(
                        objectMapper.writeValueAsString(Map.of("cred1", List.of(license), "cred2", List.of(member))),
                        query)))
                .hasMessageContaining("type does not match");
        assertThatThrownBy(() -> processor.process(dcqlRequest(member, query))).hasMessageContaining("require a JSON");
    }

    @Test
    void invalidSecondProofRejectsWholeResponse() throws Exception {
        String member = presentation("Membership", "Alice", "nonce");
        String wrongNonce = presentation("License", "Alice", "other-login");
        String wrapper =
                objectMapper.writeValueAsString(Map.of("cred1", List.of(member), "cred2", List.of(wrongNonce)));
        assertThatThrownBy(() -> processor.process(dcqlRequest(wrapper, query("Membership", "License"))))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("nonce");
    }

    @Test
    void invalidSecondSignatureAndRevokedSecondCredentialRejectWholeResponse() throws Exception {
        String member = presentation("Membership", "Alice", "nonce");
        String license = presentation("License", "Alice", "nonce");
        String[] parts = license.split("~", -1);
        SignedJWT jwt = SignedJWT.parse(parts[0]);
        SignedJWT tampered = new SignedJWT(
                jwt.getHeader(),
                new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
                        .subject("Mallory")
                        .build());
        ECKey wrongKey = new ECKeyGenerator(Curve.P_256).generate();
        tampered.sign(new ECDSASigner(wrongKey));
        String invalid = buildSdJwtVpWithKbJwt(tampered.serialize(), "client-id", "nonce");
        String query = query("Membership", "License");
        assertThatThrownBy(() -> processor.process(dcqlRequest(
                        objectMapper.writeValueAsString(Map.of("cred1", List.of(member), "cred2", List.of(invalid))),
                        query)))
                .isInstanceOf(IdentityBrokerException.class);
        StatusListVerifier status = org.mockito.Mockito.mock(StatusListVerifier.class);
        org.mockito.Mockito.doAnswer(invocation -> {
                    Map<String, Object> claims = invocation.getArgument(0);
                    if ("License".equals(claims.get("vct"))) throw new IllegalStateException("Credential revoked");
                    return null;
                })
                .when(status)
                .checkRevocationStatus(org.mockito.ArgumentMatchers.anyMap());
        VpTokenProcessor withStatus =
                new VpTokenProcessor(objectMapper, status, new TrustListProvider(List.of(signingCert)));
        assertThatThrownBy(() -> withStatus.process(dcqlRequest(
                        objectMapper.writeValueAsString(Map.of("cred1", List.of(member), "cred2", List.of(license))),
                        query)))
                .hasMessageContaining("revoked");
        org.mockito.Mockito.verify(status, org.mockito.Mockito.times(2))
                .checkRevocationStatus(org.mockito.ArgumentMatchers.anyMap());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(
            strings = {
                "{}", "{\"unknown\":[\"invalid\"]}", "{\"cred1\":[]}", "{\"cred1\":[null]}",
                "{\"cred1\":[42]}", "{\"cred1\":[{}]}", "{\"cred1\":[\"\"]}", "{\"cred1\":\"invalid\"}",
                "{\"cred1\":[\"invalid\"],\"cred1\":[\"invalid\"]}", "{\"cred1\":[\"invalid\"]} {}"
            })
    void malformedOrUnrequestedEntriesAreNeverIgnored(String wrapper) {
        assertThatThrownBy(() -> processor.process(dcqlRequest(wrapper, query("Membership"))))
                .isInstanceOf(IdentityBrokerException.class);
    }

    @Test
    void missingRequestSnapshotFailsClosed() {
        assertThatThrownBy(() -> processor.process(dcqlRequest("anything", null)))
                .hasMessageContaining("Restart the login");
    }

    @Test
    void mixedSdJwtAndMdocPresentationsAreVerifiedTogether() throws Exception {
        MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
        VpTokenProcessor mixed = new VpTokenProcessor(
                objectMapper, new StatusListVerifier(), new TrustListProvider(List.of(signingCert, helper.issuerCert)));
        String mdoc = helper.build(
                MdocSessionTranscriptBuilder.buildOid4vp("client-id", "nonce", "https://callback.example", null));
        String wrapper = objectMapper.writeValueAsString(
                Map.of("member", List.of(presentation("Membership", "Alice", "nonce")), "license", List.of(mdoc)));
        String query = """
                {"credentials":[
                  {"id":"member","format":"dc+sd-jwt","meta":{"vct_values":["Membership"]},"claims":[{"path":["sub"]}]},
                  {"id":"license","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
                   "claims":[{"path":["org.iso.18013.5.1","given_name"],"values":["John"]}]}]}
                """;
        VpTokenResult result = mixed.process(dcqlRequest(wrapper, query));
        assertThat(result.allCredentials())
                .extracting(VerifiedCredential::presentationType)
                .containsExactly(PresentationType.SD_JWT, PresentationType.MDOC);
        // An issuer-signed credential without a device proof cannot serve as the second presentation.
        String unbound = objectMapper.writeValueAsString(Map.of(
                "member", List.of(presentation("Membership", "Alice", "nonce")), "license", List.of(helper.build())));
        assertThatThrownBy(() -> mixed.process(dcqlRequest(unbound, query)))
                .hasMessageContaining("device authentication");
    }

    @Test
    void validSignedCredentialsCannotBypassClaimConditions() throws Exception {
        String wrapper = objectMapper.writeValueAsString(Map.of(
                "cred1",
                List.of(presentation("Membership", "Alice", "nonce")),
                "cred2",
                List.of(presentation("License", "Bob", "nonce"))));
        String query = query("Membership", "License")
                .replace("\"path\":[\"sub\"]", "\"path\":[\"sub\"],\"values\":[\"Alice\"]");
        assertThatThrownBy(() -> processor.process(dcqlRequest(wrapper, query)))
                .hasMessageContaining("Required claims or values");
    }

    @Test
    void duplicateIdsAndMalformedAdditionalEntriesRejectEvenWhenTheFirstCredentialIsValid() throws Exception {
        String vp = objectMapper.writeValueAsString(List.of(presentation("Membership", "Alice", "nonce")));
        String query = query("Membership");
        String duplicate = "{\"cred1\":" + vp + ",\"cred1\":" + vp + "}";
        assertThatThrownBy(() -> processor.process(dcqlRequest(duplicate, query)))
                .hasMessageContaining("Duplicate field");
        for (String suffix : List.of(",\"unknown\":[\"invalid\"]", ",\"unknown\":[]", ",\"unknown\":null")) {
            assertThatThrownBy(() -> processor.process(dcqlRequest("{\"cred1\":" + vp + suffix + "}", query)))
                    .isInstanceOf(IdentityBrokerException.class);
        }
        assertThatThrownBy(() -> processor.process(dcqlRequest("{\"cred1\":" + vp + "} {}", query)))
                .hasMessageContaining("Trailing token");
    }

    @Test
    void missingIssuerCannotBypassIssuerAllowListForAnAdditionalCredential() throws Exception {
        String signed = buildSdJwt(Map.of(
                "vct",
                "License",
                "sub",
                "Alice",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));
        String unidentifiable = buildSdJwtVpWithKbJwt(signed, "client-id", "nonce");
        String wrapper = objectMapper.writeValueAsString(Map.of(
                "cred1", List.of(presentation("Membership", "Alice", "nonce")), "cred2", List.of(unidentifiable)));
        assertThatThrownBy(() -> processor.process(dcqlRequest(wrapper, query("Membership", "License"))))
                .isInstanceOf(IdentityBrokerException.class);
    }

    private String presentation(String type, String subject, String nonce) throws Exception {
        return buildSdJwtVpWithKbJwt(
                buildSdJwt(Map.of(
                        "iss",
                        "https://issuer.example",
                        "vct",
                        type,
                        "sub",
                        subject,
                        "cnf",
                        Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))),
                "client-id",
                nonce);
    }

    private static String query(String... types) {
        java.util.List<String> entries = new java.util.ArrayList<>();
        for (int i = 0; i < types.length; i++)
            entries.add("{\"id\":\"cred" + (i + 1) + "\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\""
                    + types[i] + "\"]},\"claims\":[{\"path\":[\"sub\"]}]}");
        return "{\"credentials\":[" + String.join(",", entries) + "]}";
    }

    private static VpTokenProcessor.Request dcqlRequest(String token, String query) {
        return new VpTokenProcessor.Request(token, "client-id", "nonce", "https://callback.example", null, null, query);
    }

    @Test
    void process_unsupportedFormat_throws() {
        assertThatThrownBy(() -> processor.process(request("not-sd-jwt-or-mdoc", "client-id", "nonce", null)))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Unsupported VP token format");
    }

    @Test
    void process_nullVpToken_throws() {
        assertThatThrownBy(() -> processor.process(request(null, "client-id", "nonce", null)))
                .isInstanceOf(Exception.class);
    }

    @Test
    void process_sdJwtWithFallback_usesAlternateUri() throws Exception {
        String credJwt = buildSdJwt(Map.of(
                "iss",
                "https://issuer.example",
                "sub",
                "user1",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));
        // KB-JWT audience is the alternate URI, not the client-id
        String sdJwt = buildSdJwtVpWithKbJwt(credJwt, "https://alternate.example", "nonce");

        VpTokenResult result = processor.process(request(sdJwt, "client-id", "nonce", "https://alternate.example"));

        assertThat(result.getPrimaryCredential()).isNotNull();
    }

    // ===== Helper Methods =====

    private JWSHeader buildHeaderWithX5c() throws Exception {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(signingCert.getEncoded())))
                .build();
    }

    private String buildSdJwt(Map<String, Object> claimsMap) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        Instant now = Instant.now();
        builder.issueTime(Date.from(now));
        builder.notBeforeTime(Date.from(now));
        builder.expirationTime(Date.from(now.plusSeconds(3600)));

        SignedJWT signedJWT = new SignedJWT(buildHeaderWithX5c(), builder.build());
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize();
    }

    private String buildSdJwtVpWithKbJwt(String credJwt, String audience, String nonce) throws Exception {
        String unboundPresentation = credJwt + "~";

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(unboundPresentation.getBytes(StandardCharsets.US_ASCII));
        String sdHash = Base64URL.encode(hash).toString();

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience(audience)
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .issueTime(new Date())
                .build();
        SignedJWT kbJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                kbClaims);
        kbJwt.sign(new ECDSASigner(holderKey));

        return unboundPresentation + kbJwt.serialize();
    }

    private static X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
        ECPublicKey publicKey = ecKey.toECPublicKey();
        X500Principal subject = new X500Principal("CN=Test SD-JWT Issuer");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                publicKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(ecKey.toECPrivateKey());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    private static VpTokenProcessor.Request request(
            String vpToken, String clientId, String expectedNonce, String alternateResponseUri) {
        return new VpTokenProcessor.Request(
                vpToken,
                clientId,
                expectedNonce,
                alternateResponseUri,
                null,
                null,
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\",\"meta\":{}}]}");
    }
}
