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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderModel;

class RegistrationCertificateTest {

    private static final String RP_ID = "NTRDE-HRB123456";
    private static final String SERVICE = "login";
    private static final List<Map<String, Object>> REGISTERED = List.of(Map.of(
            "format", "dc+sd-jwt",
            "meta", Map.of("vct_values", List.of("urn:eudi:pid:1")),
            "claim", List.of(Map.of("path", List.of("given_name")), Map.of("path", List.of("address")))));

    private KeyPair registrarKeys;
    private X509Certificate registrar;
    private X509Certificate accessCertificate;

    @BeforeEach
    void setUp() throws Exception {
        registrarKeys = p256();
        registrar =
                certificate(new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Test Registrar"), registrarKeys);
        accessCertificate = certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "DE")
                        .addRDN(BCStyle.ORGANIZATION_IDENTIFIER, RP_ID)
                        .addRDN(BCStyle.OU, SERVICE)
                        .addRDN(BCStyle.CN, "Example RP"),
                p256());
    }

    @Test
    void readsTheOrganizationIdentifierOfTheAccessCertificate() {
        assertThat(RegistrationCertificate.subjectAttribute(accessCertificate, "2.5.4.97"))
                .isEqualTo(RP_ID);
        assertThat(RegistrationCertificate.subjectAttribute(accessCertificate, "OU"))
                .isEqualTo(SERVICE);
    }

    @Test
    void matchingCertificateHasNoProblems() throws Exception {
        assertThat(parse(sign("rc-wrp+jwt", claims(RP_ID, SERVICE, 30))).problems(accessCertificate, Instant.now()))
                .isEmpty();
    }

    @Test
    void reportsWhatAWalletWouldRefuse() throws Exception {
        assertThat(parse(sign("JWT", claims(RP_ID, SERVICE, 30))).problems(accessCertificate, Instant.now()))
                .singleElement()
                .asString()
                .contains("typ");
        assertThat(parse(sign("rc-wrp+jwt", claims(RP_ID, SERVICE, -1))).problems(accessCertificate, Instant.now()))
                .singleElement()
                .asString()
                .contains("expired");
        assertThat(parse(sign("rc-wrp+jwt", claims("NTRDE-OTHER", SERVICE, 30)))
                        .problems(accessCertificate, Instant.now()))
                .singleElement()
                .asString()
                .contains("organizationIdentifier");
        assertThat(parse(sign("rc-wrp+jwt", claims(RP_ID, "other-service", 30)))
                        .problems(accessCertificate, Instant.now()))
                .singleElement()
                .asString()
                .contains("organizationalUnit");
        assertThat(parse(sign("rc-wrp+jwt", claims(RP_ID, SERVICE, 30))).problems(null, Instant.now()))
                .singleElement()
                .asString()
                .contains("without an access certificate");

        String jwt = sign("rc-wrp+jwt", claims(RP_ID, SERVICE, 30));
        String tampered = jwt.substring(0, jwt.length() - 4) + (jwt.endsWith("AAAA") ? "BBBB" : "AAAA");
        assertThat(parse(tampered).problems(accessCertificate, Instant.now()))
                .anySatisfy(problem -> assertThat(problem).contains("signature"));
    }

    @Test
    void intermediariesAreBoundThroughActSubOnly() throws Exception {
        JWTClaimsSet intermediated = new JWTClaimsSet.Builder(claims("NTRDE-INTERMEDIATED", "their-service", 30))
                .claim("act", Map.of("sub", RP_ID))
                .build();

        assertThat(parse(sign("rc-wrp+jwt", intermediated)).problems(accessCertificate, Instant.now()))
                .isEmpty();
    }

    @Test
    void overAskingListsUnregisteredTypesAndClaims() throws Exception {
        RegistrationCertificate certificate = parse(sign("rc-wrp+jwt", claims(RP_ID, SERVICE, 30)));
        String query = """
                {"credentials":[
                  {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
                   "claims":[{"path":["given_name"]},{"path":["address","street_address"]},{"path":["birthdate"]}]},
                  {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
                   "claims":[{"path":["org.iso.18013.5.1","age_over_18"]}]}]}
                """;

        assertThat(certificate.overAsking(query))
                .containsExactly("birthdate of urn:eudi:pid:1", "org.iso.18013.5.1.mDL");
    }

    @Test
    void travelsBase64urlEncodedInVerifierInfo() throws Exception {
        String jwt = sign("rc-wrp+jwt", claims(RP_ID, SERVICE, 30));
        Map<String, Object> entry = parse(jwt).verifierInfoEntry();

        assertThat(entry).containsEntry("format", "registration_cert");
        String data = (String) entry.get("data");
        assertThat(new String(java.util.Base64.getUrlDecoder().decode(data), StandardCharsets.US_ASCII))
                .isEqualTo(jwt);
        assertThat(RegistrationCertificate.parse(data).claims().path("sub").asText())
                .isEqualTo(RP_ID);
    }

    @Test
    void configAddsTheCertificateToVerifierInfoOnce() throws Exception {
        String jwt = sign("rc-wrp+jwt", claims(RP_ID, SERVICE, 30));
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig(new IdentityProviderModel());
        config.getConfig().put(Oid4vpIdentityProviderConfig.REGISTRATION_CERTIFICATE, jwt);

        assertThat(config.getRequestVerifierInfo()).contains("\"format\":\"registration_cert\"");

        config.setVerifierInfo("[{\"format\":\"jwt\",\"data\":\"x\"}]");
        assertThat(config.getRequestVerifierInfo())
                .contains("\"format\":\"jwt\"")
                .contains("registration_cert");

        String own = "[{\"format\":\"registration_cert\",\"data\":\"mine\"}]";
        config.setVerifierInfo(own);
        assertThat(config.getRequestVerifierInfo()).isEqualTo(own);
    }

    private JWTClaimsSet claims(String subject, String service, int daysValid) {
        return new JWTClaimsSet.Builder()
                .subject(subject)
                .claim("name", "Example RP")
                .claim("serviceIdentifier", service)
                .claim("credentials", REGISTERED)
                .issueTime(Date.from(Instant.now().minus(1, ChronoUnit.DAYS)))
                .expirationTime(Date.from(Instant.now().plus(daysValid, ChronoUnit.DAYS)))
                .build();
    }

    private String sign(String typ, JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType(typ))
                        .x509CertChain(List.of(Base64.encode(registrar.getEncoded())))
                        .build(),
                claims);
        jwt.sign(new ECDSASigner((ECPrivateKey) registrarKeys.getPrivate()));
        return jwt.serialize();
    }

    private static RegistrationCertificate parse(String jwt) {
        return RegistrationCertificate.parse(jwt);
    }

    private static X509Certificate certificate(X500NameBuilder subject, KeyPair keys) throws Exception {
        var name = subject.build();
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(
                                name,
                                BigInteger.valueOf(System.nanoTime()),
                                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                                Date.from(Instant.now().plus(30, ChronoUnit.DAYS)),
                                name,
                                keys.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }

    private static KeyPair p256() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
