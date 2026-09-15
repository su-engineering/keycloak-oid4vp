/*
 * Copyright 2026 su-engineering contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.suengineering.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.models.KeycloakSession;

/** Exercises the real DID resolver and SD-JWT verifier together, with only HTTPS transport stubbed. */
class DidWebCredentialVerificationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ISSUER = "did:web:issuer.example";
    private static final String AUDIENCE = "https://verifier.example";
    private static final String NONCE = "fresh-login-nonce";

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(DidWebCredentialVerificationTest.class.getClassLoader());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "EdDSA"})
    void verifiesDidIssuedCredentialWithDisclosureAndHolderBinding(String algorithm) throws Exception {
        exercise(algorithm, "valid");
    }

    @ParameterizedTest
    @ValueSource(strings = {"wrong-issuer-key", "expired", "wrong-nonce", "wrong-audience", "tampered-disclosure"})
    void rejectsInvalidDidPresentation(String scenario) throws Exception {
        exercise("ES256", scenario);
    }

    private void exercise(String algorithm, String scenario) throws Exception {
        ECKey ecIssuer = new ECKeyGenerator(Curve.P_256).generate();
        KeyPair edIssuer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        Map<String, Object> publicJwk;
        if (algorithm.equals("EdDSA")) {
            byte[] encoded = edIssuer.getPublic().getEncoded();
            publicJwk = Map.of(
                    "kty",
                    "OKP",
                    "crv",
                    "Ed25519",
                    "x",
                    b64(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length)));
        } else {
            publicJwk = ecIssuer.toPublicJWK().toJSONObject();
        }
        String document = JSON.writeValueAsString(Map.of(
                "id", ISSUER,
                "verificationMethod",
                        List.of(Map.of(
                                "id",
                                ISSUER + "#issuer-key",
                                "type",
                                "JsonWebKey2020",
                                "controller",
                                ISSUER,
                                "publicKeyJwk",
                                publicJwk)),
                "assertionMethod", List.of(ISSUER + "#issuer-key")));
        String disclosure = b64(JSON.writeValueAsBytes(List.of("random-test-salt", "age_over_18", true)));
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .claim("vct", "AgeOverEighteenCredential")
                .claim("sub", "holder-123")
                // A valid credential issued long before this login must remain usable.
                .issueTime(Date.from(now.minusSeconds(30 * 86400)))
                .expirationTime(Date.from(scenario.equals("expired") ? now.minusSeconds(3600) : now.plusSeconds(86400)))
                .claim("_sd_alg", "sha-256")
                .claim("_sd", List.of(hash(disclosure)))
                .claim("cnf", Map.of("jwk", holder.toPublicJWK().toJSONObject()))
                .build();
        String issuerJwt;
        if (algorithm.equals("EdDSA")) {
            String input = b64(JSON.writeValueAsBytes(
                            Map.of("alg", "EdDSA", "typ", "dc+sd-jwt", "kid", ISSUER + "#issuer-key")))
                    + "." + b64(claims.toString().getBytes(StandardCharsets.UTF_8));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(edIssuer.getPrivate());
            signer.update(input.getBytes(StandardCharsets.US_ASCII));
            issuerJwt = input + "." + b64(signer.sign());
        } else {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("dc+sd-jwt"))
                            .keyID(ISSUER + "#issuer-key")
                            .build(),
                    claims);
            jwt.sign(new ECDSASigner(
                    scenario.equals("wrong-issuer-key") ? new ECKeyGenerator(Curve.P_256).generate() : ecIssuer));
            issuerJwt = jwt.serialize();
        }
        String unbound = issuerJwt + "~" + disclosure + "~";
        JWTClaimsSet binding = new JWTClaimsSet.Builder()
                .audience(scenario.equals("wrong-audience") ? "https://other.example" : AUDIENCE)
                .claim("nonce", scenario.equals("wrong-nonce") ? "stale-login-nonce" : NONCE)
                .claim("sd_hash", hash(unbound))
                .issueTime(Date.from(now))
                .build();
        SignedJWT kbJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                binding);
        kbJwt.sign(new ECDSASigner(holder));
        if (scenario.equals("tampered-disclosure")) {
            unbound = issuerJwt + "~" + b64(JSON.writeValueAsBytes(List.of("random-test-salt", "age_over_18", false)))
                    + "~";
        }
        String presentation = unbound + kbJwt.serialize();
        KeycloakSession session = mock(KeycloakSession.class);
        SimpleHttp http = mock(SimpleHttp.class);
        when(http.header("Accept", "application/did+json,application/json")).thenReturn(http);
        when(http.asString()).thenReturn(document);
        try (var requests = mockStatic(SimpleHttp.class)) {
            requests.when(() -> SimpleHttp.doGet("https://issuer.example/.well-known/did.json", session))
                    .thenReturn(http);
            SdJwtVerifier verifier = new SdJwtVerifier(60, 300, new DidWebResolver(session, 3600));
            if (scenario.equals("valid")) {
                var result = verifier.verify(presentation, AUDIENCE, NONCE, List.of());
                assertThat(result.issuer()).isEqualTo(ISSUER);
                assertThat(result.credentialType()).isEqualTo("AgeOverEighteenCredential");
                assertThat(result.claims()).containsEntry("age_over_18", true).containsEntry("sub", "holder-123");
            } else {
                assertThatThrownBy(() -> verifier.verify(presentation, AUDIENCE, NONCE, List.of()))
                        .isInstanceOf(IllegalStateException.class);
            }
            requests.verify(() -> SimpleHttp.doGet("https://issuer.example/.well-known/did.json", session));
        }
    }

    private static String hash(String value) throws Exception {
        return b64(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));
    }

    private static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
