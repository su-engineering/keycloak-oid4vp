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
package io.github.suengineering.keycloak.oid4vp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpJwk;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpResponseMode;
import io.github.suengineering.keycloak.oid4vp.domain.RequestObjectParams;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mockito;

class Oid4vpRedirectFlowServiceDcApiTest {

    private static final String ORIGIN = "https://login.example.com";
    private static final String DCQL =
            "{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"urn:eudi:pid:1\"]},\"claims\":[{\"path\":[\"given_name\"]}]}]}";

    private Oid4vpRedirectFlowService service;
    private ECKey signingKey;
    private String certPem;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpRedirectFlowServiceDcApiTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new Oid4vpRedirectFlowService(Mockito.mock(KeycloakSession.class), 300);
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate cert = certificateFor(signingKey);
        certPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    @Test
    @SuppressWarnings("unchecked")
    void plainClientIdScheme_buildsUnsignedRequestWithoutClientIdOrState() {
        Map<String, Object> request =
                service.buildDcApiRequest(params("plain", null, Oid4vpResponseMode.DC_API, null), ORIGIN);

        assertThat(request).containsEntry("protocol", "openid4vp-v1-unsigned");
        Map<String, Object> data = (Map<String, Object>) request.get("data");
        assertThat(data)
                .containsEntry("response_type", "vp_token")
                .containsEntry("response_mode", "dc_api")
                .containsEntry("nonce", "nonce-1")
                .containsKey("dcql_query")
                .doesNotContainKeys("client_id", "expected_origins", "state", "response_uri", "request");
        Map<String, Object> clientMetadata = (Map<String, Object>) data.get("client_metadata");
        assertThat(clientMetadata).containsKey("vp_formats_supported").doesNotContainKey("jwks");
    }

    @Test
    void certificateBoundSchemeWithoutCertificate_fallsBackToUnsigned() {
        Map<String, Object> request =
                service.buildDcApiRequest(params("x509_hash", null, Oid4vpResponseMode.DC_API, null), ORIGIN);

        assertThat(request).containsEntry("protocol", "openid4vp-v1-unsigned");
    }

    @Test
    @SuppressWarnings("unchecked")
    void certificateBoundScheme_buildsSignedRequestBoundToTheOrigin() throws Exception {
        Map<String, Object> request =
                service.buildDcApiRequest(params("x509_hash", certPem, Oid4vpResponseMode.DC_API, null), ORIGIN);

        assertThat(request).containsEntry("protocol", "openid4vp-v1-signed");
        String jwt = (String) ((Map<String, Object>) request.get("data")).get("request");
        SignedJWT signed = SignedJWT.parse(jwt);
        JWSVerifier verifier = new ECDSAVerifier(signingKey.toECPublicKey());
        assertThat(signed.verify(verifier)).isTrue();
        assertThat(signed.getHeader().getX509CertChain()).isNotEmpty();

        Map<String, Object> claims =
                new ObjectMapper().readValue(signed.getPayload().toString(), Map.class);
        assertThat(claims)
                .containsEntry("client_id", "x509_hash:client")
                .containsEntry("expected_origins", List.of(ORIGIN))
                .containsEntry("response_mode", "dc_api")
                .doesNotContainKeys("state", "response_uri");
    }

    @Test
    @SuppressWarnings("unchecked")
    void encryptedMode_advertisesTheGivenResponseKey() throws Exception {
        Oid4vpJwk key = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");

        Map<String, Object> request =
                service.buildDcApiRequest(params("plain", null, Oid4vpResponseMode.DC_API_JWT, key.toJson()), ORIGIN);

        Map<String, Object> data = (Map<String, Object>) request.get("data");
        assertThat(data).containsEntry("response_mode", "dc_api.jwt");
        Map<String, Object> clientMetadata = (Map<String, Object>) data.get("client_metadata");
        Map<String, Object> jwks = (Map<String, Object>) clientMetadata.get("jwks");
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        assertThat(keys).singleElement().satisfies(jwk -> {
            assertThat(jwk).containsEntry("kid", key.keyId()).doesNotContainKey("d");
        });
        assertThat(clientMetadata.get("encrypted_response_enc_values_supported"))
                .isEqualTo(List.of("A128GCM", "A256GCM"));
    }

    @Test
    void redirectResponseMode_isRejected() {
        assertThatThrownBy(() ->
                        service.buildDcApiRequest(params("plain", null, Oid4vpResponseMode.DIRECT_POST, null), ORIGIN))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private RequestObjectParams params(
            String scheme, String pem, Oid4vpResponseMode responseMode, String encryptionKeyJson) {
        return new RequestObjectParams(
                DCQL,
                null,
                "x509_hash".equals(scheme) ? "x509_hash:client" : "https://kc.example/realms/test/",
                scheme,
                null,
                "state-1",
                "nonce-1",
                pem,
                signingKey.toJSONString(),
                encryptionKeyJson,
                null,
                responseMode,
                false,
                false);
    }

    private static X509Certificate certificateFor(ECKey key) throws Exception {
        X500Principal subject = new X500Principal("CN=login.example.com");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                subject,
                key.toECPublicKey());
        builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "login.example.com")));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key.toECPrivateKey())));
    }
}
