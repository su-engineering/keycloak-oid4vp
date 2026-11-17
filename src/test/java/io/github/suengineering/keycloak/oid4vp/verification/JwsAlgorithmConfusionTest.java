/*
 * Copyright 2026 su-engineering contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.suengineering.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.common.crypto.CryptoIntegration;

/**
 * The JWS header's {@code alg} is attacker controlled. A signature check must use the algorithm the key implies, so
 * {@code none}, an HMAC algorithm keyed with the public key, and a header that names a different algorithm than the
 * one that produced the signature are all refused: both on the bare signature check and on a full SD-JWT
 * presentation whose issuer is identified by an {@code x5c} chain.
 */
class JwsAlgorithmConfusionTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ISSUER = "https://issuer.example";
    private static final String AUDIENCE = "https://verifier.example";
    private static final String NONCE = "fresh-login-nonce";

    private static KeyPair rootKeys;
    private static X509Certificate root;
    private static KeyPair issuerKeys;
    private static X509Certificate issuer;

    @BeforeAll
    static void setUp() throws Exception {
        CryptoIntegration.init(JwsAlgorithmConfusionTest.class.getClassLoader());
        rootKeys = MdocTrustTestPki.p256();
        root = certificate("CN=Test Root (synthetic)", rootKeys, "CN=Test Root (synthetic)", rootKeys, true);
        issuerKeys = MdocTrustTestPki.p256();
        issuer = certificate("CN=Test Issuer (synthetic)", issuerKeys, "CN=Test Root (synthetic)", rootKeys, false);
    }

    @Test
    void theUnmodifiedSignatureVerifies() throws Exception {
        String jwt = es256(Map.of("alg", "ES256", "typ", "JWT"), "{\"iss\":\"x\"}");
        assertThatCode(() ->
                        X5cChainValidator.verifyJwtSignature(X5cChainValidator.parseJwt(jwt), issuer.getPublicKey()))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "none-empty-signature",
                "none-original-signature",
                "hs256-public-key-as-secret",
                "es384-header",
                "es512-header",
                "rs256-header",
                "ps256-header",
                "eddsa-header",
                "lowercase-es256"
            })
    void aSignatureCheckRefusesAHeaderThatDoesNotMatchTheKey(String scenario) throws Exception {
        String jwt = forge(scenario, "{\"iss\":\"x\"}", Map.of("typ", "JWT"));
        assertThatThrownBy(() ->
                        X5cChainValidator.verifyJwtSignature(X5cChainValidator.parseJwt(jwt), issuer.getPublicKey()))
                .isInstanceOf(Exception.class);
    }

    @Test
    void aWellFormedX5cPresentationVerifies() throws Exception {
        var result = new SdJwtVerifier(60, 300).verify(presentation("valid", "valid"), AUDIENCE, NONCE, List.of(root));
        assertThat(result.issuer()).isEqualTo(ISSUER);
        assertThat(result.claims()).containsEntry("age_over_18", true);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"none-empty-signature", "none-original-signature", "hs256-public-key-as-secret", "es384-header"})
    void anIssuerJwtWithAForgedAlgorithmIsRejected(String scenario) throws Exception {
        String presentation = presentation(scenario, "valid");
        assertThatThrownBy(() -> new SdJwtVerifier(60, 300).verify(presentation, AUDIENCE, NONCE, List.of(root)))
                .isInstanceOf(Exception.class);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"none-empty-signature", "none-original-signature", "hs256-public-key-as-secret", "es384-header"})
    void aKeyBindingJwtWithAForgedAlgorithmIsRejected(String scenario) throws Exception {
        String presentation = presentation("valid", scenario);
        assertThatThrownBy(() -> new SdJwtVerifier(60, 300).verify(presentation, AUDIENCE, NONCE, List.of(root)))
                .isInstanceOf(Exception.class);
    }

    private static ECKey holder;

    private static String presentation(String issuerScenario, String bindingScenario) throws Exception {
        if (holder == null) {
            holder = new ECKeyGenerator(Curve.P_256).generate();
        }
        String disclosure = b64(JSON.writeValueAsBytes(List.of("random-test-salt", "age_over_18", true)));
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .claim("vct", "AgeOverEighteenCredential")
                .issueTime(Date.from(now.minusSeconds(3600)))
                .expirationTime(Date.from(now.plusSeconds(86400)))
                .claim("_sd_alg", "sha-256")
                .claim("_sd", List.of(hash(disclosure)))
                .claim("cnf", Map.of("jwk", holder.toPublicJWK().toJSONObject()))
                .build();
        Map<String, Object> issuerHeader = new LinkedHashMap<>();
        issuerHeader.put("typ", "dc+sd-jwt");
        issuerHeader.put("x5c", List.of(Base64.encode(issuer.getEncoded()).toString()));
        String issuerJwt = forge(issuerScenario, claims.toString(), issuerHeader);
        String unbound = issuerJwt + "~" + disclosure + "~";
        JWTClaimsSet binding = new JWTClaimsSet.Builder()
                .audience(AUDIENCE)
                .claim("nonce", NONCE)
                .claim("sd_hash", hash(unbound))
                .issueTime(Date.from(now))
                .build();
        String kbJwt;
        if (bindingScenario.equals("valid")) {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("kb+jwt"))
                            .build(),
                    binding);
            jwt.sign(new ECDSASigner(holder));
            kbJwt = jwt.serialize();
        } else {
            kbJwt = forgeWith(
                    bindingScenario,
                    binding.toString(),
                    Map.of("typ", "kb+jwt"),
                    holder.toECPrivateKey(),
                    holder.toECPublicKey());
        }
        return unbound + kbJwt;
    }

    /** A JWT signed by the issuer key, then altered as the scenario says. */
    private static String forge(String scenario, String payload, Map<String, Object> header) throws Exception {
        return forgeWith(scenario, payload, header, (ECPrivateKey) issuerKeys.getPrivate(), (ECPublicKey)
                issuerKeys.getPublic());
    }

    private static String forgeWith(
            String scenario, String payload, Map<String, Object> header, ECPrivateKey key, ECPublicKey publicKey)
            throws Exception {
        String body = b64(payload.getBytes(StandardCharsets.UTF_8));
        if (scenario.equals("valid")) {
            return es256(with(header, "ES256"), payload, key);
        }
        String genuine = es256(with(header, "ES256"), payload, key);
        String signature = genuine.substring(genuine.lastIndexOf('.') + 1);
        String alg =
                switch (scenario) {
                    case "none-empty-signature", "none-original-signature" -> "none";
                    case "hs256-public-key-as-secret" -> "HS256";
                    case "es384-header" -> "ES384";
                    case "es512-header" -> "ES512";
                    case "rs256-header" -> "RS256";
                    case "ps256-header" -> "PS256";
                    case "eddsa-header" -> "EdDSA";
                    case "lowercase-es256" -> "es256";
                    default -> throw new IllegalArgumentException(scenario);
                };
        String input = b64(JSON.writeValueAsBytes(with(header, alg))) + "." + body;
        return switch (scenario) {
            case "none-empty-signature" -> input + ".";
            case "hs256-public-key-as-secret" -> {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(publicKey.getEncoded(), "HmacSHA256"));
                yield input + "." + b64(mac.doFinal(input.getBytes(StandardCharsets.US_ASCII)));
            }
            default -> input + "." + signature;
        };
    }

    private static Map<String, Object> with(Map<String, Object> header, String alg) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("alg", alg);
        result.putAll(header);
        return result;
    }

    private static String es256(Map<String, Object> header, String payload) throws Exception {
        return es256(header, payload, (ECPrivateKey) issuerKeys.getPrivate());
    }

    private static String es256(Map<String, Object> header, String payload, ECPrivateKey key) throws Exception {
        String input = b64(JSON.writeValueAsBytes(header)) + "." + b64(payload.getBytes(StandardCharsets.UTF_8));
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(key);
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64(signer.sign());
    }

    private static X509Certificate certificate(
            String subject, KeyPair subjectKeys, String issuerName, KeyPair signer, boolean ca) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerName),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Principal(subject),
                subjectKeys.getPublic());
        builder.addExtension(
                Extension.basicConstraints, true, ca ? new BasicConstraints(0) : new BasicConstraints(false));
        builder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (!ca) {
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, ISSUER)));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
    }

    private static String hash(String value) throws Exception {
        return b64(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));
    }

    private static String b64(byte[] value) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
