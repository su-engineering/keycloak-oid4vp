/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.common.crypto.CryptoIntegration;

class DidWebVhCredentialVerificationTest {
    @BeforeAll
    static void crypto() {
        CryptoIntegration.init(DidWebVhCredentialVerificationTest.class.getClassLoader());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "ES256",
                "EdDSA",
                "bad-signature",
                "wrong-nonce",
                "wrong-audience",
                "expired",
                "bad-disclosure",
                "unknown-kid",
                "tampered-history",
                "method-disabled"
            })
    void verifiesPresentationThroughRealHistoryResolver(String scenario) throws Exception {
        ECKey ec = new ECKeyGenerator(Curve.P_256).generate();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        var ed = new WebVhTestLog.TestSigner();
        boolean edDsa = scenario.equals("EdDSA");
        JsonObject key = edDsa
                ? ed.publicKey()
                : JsonParser.parseString(ec.toPublicJWK().toJSONString()).getAsJsonObject();
        var log = new WebVhTestLog(key);
        String disclosure = b64("[\"test-salt\",\"active\",true]".getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        var claims = new JWTClaimsSet.Builder()
                .issuer(log.did)
                .subject("member-123")
                .claim("vct", "https://credentials.example/membership")
                .issueTime(Date.from(now.minusSeconds(86400)))
                .expirationTime(Date.from(now.plusSeconds(scenario.equals("expired") ? -3600 : 3600)))
                .claim("_sd_alg", "sha-256")
                .claim("_sd", List.of(hash(disclosure)))
                .claim("cnf", Map.of("jwk", holder.toPublicJWK().toJSONObject()))
                .build();
        String kid = log.did + (scenario.equals("unknown-kid") ? "#unknown" : "#issuer-key");
        String jwt;
        if (edDsa) {
            String input =
                    b64(DidWebVhLog.JSON.writeValueAsBytes(Map.of("alg", "EdDSA", "typ", "dc+sd-jwt", "kid", kid)))
                            + "." + b64(claims.toString().getBytes(StandardCharsets.UTF_8));
            jwt = input + "." + b64(ed.sign(input.getBytes(StandardCharsets.US_ASCII)));
        } else {
            SignedJWT signed = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(kid)
                            .type(new JOSEObjectType("dc+sd-jwt"))
                            .build(),
                    claims);
            signed.sign(new ECDSASigner(
                    scenario.equals("bad-signature") ? new ECKeyGenerator(Curve.P_256).generate() : ec));
            jwt = signed.serialize();
        }
        String unbound = jwt + "~" + disclosure + "~";
        SignedJWT binding = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                new JWTClaimsSet.Builder()
                        .audience(scenario.equals("wrong-audience") ? "other" : "verifier")
                        .claim("nonce", scenario.equals("wrong-nonce") ? "old" : "nonce")
                        .claim("sd_hash", hash(unbound))
                        .issueTime(Date.from(now))
                        .build());
        binding.sign(new ECDSASigner(holder));
        if (scenario.equals("bad-disclosure")) {
            unbound = jwt + "~" + b64("[\"test-salt\",\"active\",false]".getBytes(StandardCharsets.UTF_8)) + "~";
        }
        String presentation = unbound + binding.serialize();
        var resolver = new DidWebVhResolver(
                url -> scenario.equals("tampered-history")
                        ? log.jsonl().replace("issuer-key", "other-key")
                        : log.jsonl(),
                0,
                Clock.systemUTC());
        var configured = new ConfiguredDidResolver(
                scenario.equals("method-disabled") ? "did:web" : "did:web, did:webvh", List.of(resolver));
        var verifier = new SdJwtVerifier(30, 120, configured);
        if (scenario.equals("ES256") || edDsa) {
            var result = verifier.verify(presentation, "verifier", "nonce", List.of());
            assertThat(result.issuer()).isEqualTo(log.did);
            assertThat(result.credentialType()).isEqualTo("https://credentials.example/membership");
            assertThat(result.claims()).containsEntry("active", true).containsEntry("sub", "member-123");
        } else {
            assertThatThrownBy(() -> verifier.verify(presentation, "verifier", "nonce", List.of()))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void dispatchesOnlyExplicitMethodsWithExactPrefixMatching() {
        DidResolver web = mock(DidResolver.class);
        DidResolver webvh = mock(DidResolver.class);
        String did = "did:webvh:QmExample:issuer.example";
        when(webvh.supports(did)).thenReturn(true);
        var restricted = new ConfiguredDidResolver("did:web", List.of(web, webvh));
        assertThat(restricted.supports(did)).isFalse();
        assertThatThrownBy(() -> restricted.resolve(did, null)).hasMessageContaining("not enabled");
        verifyNoInteractions(web, webvh);
        var enabled = new ConfiguredDidResolver("did:web, did:webvh", List.of(web, webvh));
        assertThat(enabled.supports(did)).isTrue();
        enabled.resolve(did, "#key");
        verify(webvh).resolve(did, "#key");
        verify(web, never()).resolve(any(), any());
        assertThat(enabled.supports("did:webvhh:QmExample:issuer.example")).isFalse();
    }

    private static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String hash(String value) throws Exception {
        return b64(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));
    }
}
