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
package io.github.suengineering.keycloak.oid4vp.it;

import static org.assertj.core.api.Assertions.assertThat;

import com.microsoft.playwright.Page;
import com.microsoft.playwright.options.WaitForSelectorState;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.jose.jws.JWSInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;

/**
 * Signs in through the W3C Digital Credentials API (OID4VP 1.0 Appendix A).
 *
 * <p>Headless Chromium has no wallet behind {@code navigator.credentials.get()}, so the test
 * replaces it with a stub that forwards the request to a real wallet's Digital Credentials API
 * endpoint, sending the page origin the way a browser would. The wallet builds the presentation
 * for that origin, and Keycloak verifies it.
 */
class KeycloakOid4vpDcApiE2eIT extends AbstractOid4vpE2eTest {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpDcApiE2eIT.class);
    private static final String DC_API_WALLET_INTERNAL_URL = Oid4vpE2eEnvironment.DC_API_WALLET_INTERNAL_BASE_URL;

    private static final String SD_JWT_QUERY = """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
              "claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}
            """;
    private static final String MDOC_QUERY = """
            {"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},
              "claims":[{"path":["eu.europa.ec.eudi.pid.1","family_name"]},
                        {"path":["eu.europa.ec.eudi.pid.1","given_name"]}]}]}
            """;

    private final HttpClient http =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final AtomicReference<String> originOverride = new AtomicReference<>();
    private GenericContainer<?> dcApiWallet;
    private String trustListSigningCertPem;

    @BeforeAll
    void readWalletTrustList() throws Exception {
        dcApiWallet = env.dcApiWallet();
        trustListSigningCertPem = leafCertificateOf(get("/api/trustlists/pid"));
    }

    @BeforeEach
    void installDigitalCredentialsStub() throws Exception {
        originOverride.set(null);
        isoMdocWallet = false;
        isoReaderAuthVerified = false;
        context.exposeFunction("__walletDcApi", args -> callWallet((String) args[0]));
        context.addInitScript("""
                (() => {
                  window.DigitalCredential = function DigitalCredential() {};
                  Object.defineProperty(navigator.credentials, "get", {
                    configurable: true,
                    value: async (options) => {
                      const result = JSON.parse(await window.__walletDcApi(JSON.stringify({ digital: options.digital })));
                      return { protocol: result.protocol, data: result.data };
                    }
                  });
                })();
                """);
        idpConfig
                .set(Oid4vpIdentityProviderConfig.DC_API_ENABLED, "true")
                .set(Oid4vpIdentityProviderConfig.TRUST_LIST_URL, DC_API_WALLET_INTERNAL_URL + "/api/trustlists/pid")
                .set(Oid4vpIdentityProviderConfig.TRUST_LIST_SIGNING_CERT_PEM, trustListSigningCertPem)
                .set(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM, "family_name")
                .set(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC, "eu.europa.ec.eudi.pid.1/family_name");
    }

    @Test
    void signedRequestSdJwtLogin() throws Exception {
        idpConfig.set(Oid4vpIdentityProviderConfig.DCQL_QUERY, SD_JWT_QUERY).apply();

        loginThroughDigitalCredentialsApi("dcapi-sdjwt");

        // HAIP is on in this environment: a signed request with an encrypted response.
        assertThat(lastProtocol.get()).isEqualTo("openid4vp-v1-signed");
        String requestObject = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(lastRequestBody.get())
                .at("/digital/requests/0/data/request")
                .asText();
        String claims =
                new String(Base64.getUrlDecoder().decode(requestObject.split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(claims).contains("\"response_mode\":\"dc_api.jwt\"").contains("\"expected_origins\"");
    }

    @Test
    void unsignedRequestMdocLogin() throws Exception {
        idpConfig
                .set(Oid4vpIdentityProviderConfig.DCQL_QUERY, MDOC_QUERY)
                .set(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false")
                .set(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "plain")
                .set(Oid4vpIdentityProviderConfig.RESPONSE_MODE, "direct_post")
                .apply();

        loginThroughDigitalCredentialsApi("dcapi-mdoc");

        assertThat(lastProtocol.get()).isEqualTo("openid4vp-v1-unsigned");
        assertThat(lastRequestBody.get()).contains("\"response_mode\":\"dc_api\"");
    }

    @Test
    void unsignedRequestEncryptedResponseLogin() throws Exception {
        idpConfig
                .set(Oid4vpIdentityProviderConfig.DCQL_QUERY, SD_JWT_QUERY)
                .set(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false")
                .set(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "plain")
                .set(Oid4vpIdentityProviderConfig.RESPONSE_MODE, "direct_post.jwt")
                .apply();

        loginThroughDigitalCredentialsApi("dcapi-encrypted");

        assertThat(lastProtocol.get()).isEqualTo("openid4vp-v1-unsigned");
        assertThat(lastRequestBody.get())
                .contains("\"response_mode\":\"dc_api.jwt\"")
                .contains("\"jwks\"");
    }

    @Test
    void presentationForAnotherOriginIsRejected() throws Exception {
        idpConfig.set(Oid4vpIdentityProviderConfig.DCQL_QUERY, MDOC_QUERY).apply();
        originOverride.set("https://attacker.example");

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        clickDcApiButton();

        page.waitForURL(url -> url.contains("error="), new Page.WaitForURLOptions().setTimeout(30000));
        page.waitForLoadState();
        String body = page.locator("body").textContent().toLowerCase();
        assertThat(flow.isCallbackUrl(page.url())).as("Login must not succeed").isFalse();
        assertThat(body).containsAnyOf("deviceauth", "failed", "error", "invalid");
    }

    @Test
    void isoMdocLoginLikeSafari() throws Exception {
        // Safari and Apple Wallet answer only ISO/IEC 18013-7 Annex C (org-iso-mdoc).
        idpConfig.set(Oid4vpIdentityProviderConfig.DCQL_QUERY, MDOC_QUERY).apply();
        isoMdocWallet = true;

        loginThroughDigitalCredentialsApi("dcapi-iso");

        assertThat(lastProtocol.get()).isEqualTo("org-iso-mdoc");
        assertThat(isoReaderAuthVerified)
                .as("the request is signed with readerAuthAll")
                .isTrue();
    }

    @Test
    void isoMdocResponseForAnotherOriginIsRejected() throws Exception {
        idpConfig.set(Oid4vpIdentityProviderConfig.DCQL_QUERY, MDOC_QUERY).apply();
        isoMdocWallet = true;
        originOverride.set("https://attacker.example");

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        clickDcApiButton();

        page.waitForURL(url -> url.contains("error="), new Page.WaitForURLOptions().setTimeout(30000));
        assertThat(flow.isCallbackUrl(page.url())).as("Login must not succeed").isFalse();
    }

    @Test
    void registrationCertificateTravelsInVerifierInfo() throws Exception {
        String registrationCertificate = testRegistrationCertificate();
        idpConfig
                .set(Oid4vpIdentityProviderConfig.DCQL_QUERY, SD_JWT_QUERY)
                .set(Oid4vpIdentityProviderConfig.REGISTRATION_CERTIFICATE, registrationCertificate)
                .apply();

        loginThroughDigitalCredentialsApi("dcapi-rc");

        String requestObject = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(lastRequestBody.get())
                .at("/digital/requests/0/data/request")
                .asText();
        var claims = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(Base64.getUrlDecoder().decode(requestObject.split("\\.")[1]));
        var entry = claims.path("verifier_info").get(0);
        assertThat(entry.path("format").asText()).isEqualTo("registration_cert");
        assertThat(new String(Base64.getUrlDecoder().decode(entry.path("data").asText()), StandardCharsets.US_ASCII))
                .isEqualTo(registrationCertificate);
    }

    /** A self-signed rc-wrp+jwt; this wallet runs without ARF checks, so only its transport is under test. */
    private static String testRegistrationCertificate() throws Exception {
        var keys = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate();
        var jwt = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .type(new com.nimbusds.jose.JOSEObjectType("rc-wrp+jwt"))
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .subject("NTRDE-TEST")
                        .claim("name", "Test RP")
                        .expirationTime(new java.util.Date(System.currentTimeMillis() + 86_400_000L))
                        .build());
        jwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(keys));
        return jwt.serialize();
    }

    @Test
    void buttonStaysHiddenWithoutBrowserSupport() throws Exception {
        idpConfig.set(Oid4vpIdentityProviderConfig.DCQL_QUERY, SD_JWT_QUERY).apply();
        context.addInitScript("delete window.DigitalCredential;");

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        page.waitForSelector(
                "#oid4vp-dc-api-config", new Page.WaitForSelectorOptions().setState(WaitForSelectorState.ATTACHED));

        assertThat(page.locator("#oid4vp-dc-api-button").isVisible()).isFalse();
    }

    private final AtomicReference<String> lastProtocol = new AtomicReference<>();
    private final AtomicReference<String> lastRequestBody = new AtomicReference<>();
    private volatile boolean isoMdocWallet;
    private volatile boolean isoReaderAuthVerified;

    private void loginThroughDigitalCredentialsApi(String usernamePrefix) {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        clickDcApiButton();
        flow.waitForLoginCompletion(new Oid4vpLoginFlowHelper.WalletResponse("", null));
        // The wallet PID's family name is prefilled as username and may contain characters Keycloak rejects.
        if (page.locator("input[name='username']").count() > 0) {
            page.locator("input[name='username']").fill(usernamePrefix + "-" + System.currentTimeMillis());
        }
        flow.completeFirstBrokerLoginIfNeeded(usernamePrefix);
        flow.assertLoginSucceeded();
    }

    private void clickDcApiButton() {
        page.waitForSelector(
                "#oid4vp-dc-api-button",
                new Page.WaitForSelectorOptions()
                        .setState(WaitForSelectorState.VISIBLE)
                        .setTimeout(30000));
        page.locator("#oid4vp-dc-api-button").click();
    }

    /** What the browser does for {@code navigator.credentials.get()}: hand the request to the wallet with the page origin. */
    private String callWallet(String requestJson) {
        try {
            lastRequestBody.set(requestJson);
            String origin = originOverride.get() != null ? originOverride.get() : pageOrigin();
            if (isoMdocWallet) {
                IsoMdocTestWallet.Answer answer = IsoMdocTestWallet.answer(
                        requestJson,
                        origin,
                        issuedMdoc(),
                        env.dcApiWalletHolderKey().getPrivate());
                isoReaderAuthVerified = answer.readerAuthVerified();
                lastProtocol.set("org-iso-mdoc");
                return answer.credentialJson();
            }
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(URI.create(walletHostUrl() + "/api/dc-api"))
                            .timeout(Duration.ofSeconds(30))
                            .header("Content-Type", "application/json")
                            .header("Origin", origin)
                            .POST(HttpRequest.BodyPublishers.ofString(requestJson))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            LOG.info("[Test] DC API wallet answered {}: {}", response.statusCode(), abbreviate(response.body()));
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Wallet refused the request: " + response.body());
            }
            String protocol = new com.fasterxml.jackson.databind.ObjectMapper()
                    .readTree(response.body())
                    .path("protocol")
                    .asText();
            lastProtocol.set(protocol);
            return response.body();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Wallet call failed: " + e.getMessage(), e);
        }
    }

    /** The IssuerSigned structure of the wallet's PID mdoc, base64url. */
    private String issuedMdoc() throws Exception {
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        for (var credential : mapper.readTree(get("/api/credentials"))) {
            if ("mso_mdoc".equals(credential.path("format").asText())) {
                return mapper.readTree(
                                get("/api/credentials/" + credential.path("id").asText()))
                        .path("raw")
                        .asText();
            }
        }
        throw new IllegalStateException("The DC API wallet holds no mdoc");
    }

    private String pageOrigin() {
        URI keycloak = URI.create(env.keycloakHostUrl());
        return keycloak.getScheme() + "://" + keycloak.getHost() + ":" + keycloak.getPort();
    }

    private String walletHostUrl() {
        return "http://" + dcApiWallet.getHost() + ":" + dcApiWallet.getMappedPort(8085);
    }

    private String get(String path) throws Exception {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(walletHostUrl() + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as("GET %s", path).isEqualTo(200);
        return response.body().trim();
    }

    private static String leafCertificateOf(String jwt) throws Exception {
        List<String> x5c = new JWSInput(jwt).getHeader().getX5c();
        assertThat(x5c).as("trust list x5c").isNotEmpty();
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(Base64.getMimeDecoder().decode(x5c.get(0)));
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----";
    }

    private static String abbreviate(String value) {
        return value.length() > 300 ? value.substring(0, 300) + "..." : value;
    }
}
