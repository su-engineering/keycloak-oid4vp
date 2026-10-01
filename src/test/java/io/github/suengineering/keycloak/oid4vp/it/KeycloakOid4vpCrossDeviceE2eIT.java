/*
 * Copyright 2026 Bundesagentur für Arbeit
 * Modified by su-engineering: package namespace migration and cross-device status polling (2026).
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

import com.fasterxml.jackson.databind.JsonNode;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class KeycloakOid4vpCrossDeviceE2eIT extends AbstractOid4vpE2eTest {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpCrossDeviceE2eIT.class);

    @Test
    void crossDeviceFirstLogin() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        idpConfig.set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true").apply();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        LOG.info("[Test] Cross-device wallet URL: {}", walletUrl);

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        LOG.info("[Test] Cross-device wallet response: {}", walletResponse.rawBody());

        assertThat(walletResponse.redirectUri()).isNull();
        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceSecondLogin() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        idpConfig.set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true").apply();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-repeat-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceMdocPresentationFlow() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ]
                }
                """;
        idpConfig
                .set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true")
                .set(Oid4vpIdentityProviderConfig.DCQL_QUERY, mdocDcqlQuery)
                .apply();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        LOG.info("[Test] Cross-device mDoc wallet URL: {}", walletUrl);

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-mdoc-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void sameDevicePrefetchDoesNotInvalidateCrossDeviceFlow() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        idpConfig.set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true").apply();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String sameDeviceWalletUrl = flow.getSameDeviceWalletUrl();
        String crossDeviceWalletUrl = flow.getCrossDeviceWalletUrl();
        String sameDeviceRequestUri = Oid4vpLoginFlowHelper.extractRequestUri(sameDeviceWalletUrl);

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> prefetch1 = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(sameDeviceRequestUri))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> prefetch2 = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(sameDeviceRequestUri))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(prefetch1.statusCode()).isEqualTo(200);
        assertThat(prefetch2.statusCode()).isEqualTo(200);

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(crossDeviceWalletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-after-same-prefetch");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceCompletionCanBeObservedByStatusPollWithSameBrowserSession() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        idpConfig.set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true").apply();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String requestHandle = flow.getRequestHandle();

        page.navigate("about:blank");

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();
        String statusUrl = env.keycloakHostUrl() + "/realms/" + Oid4vpE2eEnvironment.REALM
                + "/broker/oid4vp/endpoint/cross-device/status?request_handle="
                + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);
        String cookieHeader = browserCookieHeader(statusUrl);
        HttpResponse<String> statusResponse = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(statusUrl))
                                .header("Cookie", cookieHeader)
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(statusResponse.statusCode()).isEqualTo(200);
        assertThat(statusResponse.headers().firstValue("Cache-Control"))
                .hasValueSatisfying(value -> assertThat(value).contains("no-store"));
        JsonNode status = env.objectMapper().readTree(statusResponse.body());
        assertThat(status.path("status").asText()).isEqualTo("complete");
        String redirectUri = status.path("redirect_uri").asText();
        assertThat(redirectUri).contains("complete-auth");

        page.navigate(redirectUri);
        flow.completeFirstBrokerLoginIfNeeded("cross-device-status-poll-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceStatusWithoutBrowserSessionCookieReturnsNoContent() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        idpConfig.set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true").apply();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String requestHandle = flow.getRequestHandle();

        page.navigate("about:blank");

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        String statusUrl = env.keycloakHostUrl() + "/realms/" + Oid4vpE2eEnvironment.REALM
                + "/broker/oid4vp/endpoint/cross-device/status?request_handle="
                + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);
        HttpResponse<String> statusResponse = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(statusUrl))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(statusResponse.statusCode()).isEqualTo(204);
        assertThat(statusResponse.body()).isEmpty();
    }

    @Test
    void crossDeviceCompleteAuthWithoutBrowserSessionCookieIsRejected() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        idpConfig.set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true").apply();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String requestHandle = flow.getRequestHandle();

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        String completeAuthUrl = env.keycloakHostUrl() + "/realms/" + Oid4vpE2eEnvironment.REALM
                + "/broker/oid4vp/endpoint/complete-auth?request_handle="
                + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);

        var otherContext = env.newBrowserContext();
        var otherPage = otherContext.newPage();
        try {
            otherPage.navigate(completeAuthUrl);
            otherPage.waitForLoadState();
            assertThat(otherPage.locator("body").textContent().toLowerCase())
                    .contains("authentication session does not match");
        } finally {
            otherPage.close();
            otherContext.close();
        }
    }
}
