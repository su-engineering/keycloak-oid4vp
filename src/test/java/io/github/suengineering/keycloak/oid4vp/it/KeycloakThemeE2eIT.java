/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.it;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KeycloakThemeE2eIT extends AbstractOid4vpE2eTest {
    private String previousTheme;
    private String previousBrowserFlow;

    private void useWalletFlow() throws Exception {
        String path = "/admin/realms/" + Oid4vpE2eEnvironment.REALM;
        previousBrowserFlow = String.valueOf(adminClient().getJson(path).get("browserFlow"));
        adminClient().putJson(path, Map.of("browserFlow", "wallet-browser"));
    }

    private void useTheme(String theme) throws Exception {
        String path = "/admin/realms/" + Oid4vpE2eEnvironment.REALM;
        previousTheme = String.valueOf(adminClient().getJson(path).getOrDefault("loginTheme", ""));
        adminClient().putJson(path, Map.of("loginTheme", theme));
    }

    @AfterEach
    void restoreTheme() throws Exception {
        if (previousBrowserFlow != null) {
            adminClient()
                    .putJson("/admin/realms/" + Oid4vpE2eEnvironment.REALM, Map.of("browserFlow", previousBrowserFlow));
            previousBrowserFlow = null;
        }
        if (previousTheme != null) {
            adminClient().putJson("/admin/realms/" + Oid4vpE2eEnvironment.REALM, Map.of("loginTheme", previousTheme));
            previousTheme = null;
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"openkyc", "su-engineering"})
    void sameDeviceLoginCompletesWithBundledTheme(String theme) throws Exception {
        useTheme(theme);
        useWalletFlow();
        callback().reset();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);
        navigateDirectlyToWallet();
        var response = flow.submitToWallet(flow.getSameDeviceWalletUrl());
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded("theme-same-device-user");
        flow.assertLoginSucceeded();
    }

    @ParameterizedTest
    @ValueSource(strings = {"openkyc", "su-engineering"})
    void crossDeviceLoginCompletesWithBundledTheme(String theme) throws Exception {
        useTheme(theme);
        useWalletFlow();
        callback().reset();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);
        navigateDirectlyToWallet();
        assertThat(flow.submitToWallet(flow.getCrossDeviceWalletUrl()).redirectUri())
                .isNull();
        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("theme-cross-device-user");
        flow.assertLoginSucceeded();
    }

    private void navigateDirectlyToWallet() {
        page.navigate(flow.buildAuthRequestUri().toString());
        page.waitForSelector("#oid4vp-open-wallet");
        assertThat(page.locator("#username, #password, #social-oid4vp").count()).isZero();
    }

    @Test
    void openkycProviderSelectionPreservesAuthenticationSession() throws Exception {
        useTheme("openkyc");
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        assertThat(flow.getSameDeviceWalletUrl()).isNotBlank();
    }

    @Test
    void neutralThemeLoadsLocallyAndFitsNarrowScreens() throws Exception {
        useTheme("su-engineering");
        List<String> failedAssets = new ArrayList<>();
        List<String> externalAssets = new ArrayList<>();
        List<String> pageErrors = new ArrayList<>();
        page.onPageError(pageErrors::add);
        page.onResponse(response -> {
            if (response.url().contains("/resources/") && response.status() >= 400) {
                failedAssets.add(response.url());
            }
        });
        page.onRequest(request -> {
            if (List.of("stylesheet", "font", "script", "image").contains(request.resourceType())
                    && request.url().startsWith("http")
                    && !URI.create(request.url()).getHost().equals("localhost")) {
                externalAssets.add(request.url());
            }
        });
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        flow.getCrossDeviceWalletUrl();
        assertThat(page.locator("h1").textContent()).isEqualTo("sign in with your wallet");
        assertThat(page.locator("body").textContent()).doesNotContain("OpenKYC", "AgeOverEighteen", "suWallet");
        assertThat(page.locator("a#social-oid4vp").count()).isZero();
        for (int width : new int[] {320, 390, 1440}) {
            page.setViewportSize(width, 900);
            assertThat(page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"))
                    .as("no horizontal overflow at %s px", width)
                    .isEqualTo(true);
            assertThat(page.locator("#oid4vp-qr-code").isVisible()).isTrue();
            assertThat(page.locator("#oid4vp-open-wallet").isVisible()).isTrue();
        }
        page.keyboard().press("Tab");
        assertThat(page.locator("a:focus").textContent()).isEqualTo("Skip to sign-in");
        page.keyboard().press("Enter");
        assertThat(page.url()).endsWith("#su-main");
        assertThat(failedAssets).isEmpty();
        assertThat(externalAssets).isEmpty();
        assertThat(pageErrors).isEmpty();
    }

    @Test
    void neutralThemeSupportsCrossDeviceOnly() throws Exception {
        useTheme("su-engineering");
        idpConfig.set(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED, "false").apply();
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        flow.getCrossDeviceWalletUrl();
        assertThat(page.locator("#oid4vp-open-wallet").count()).isZero();
    }

    @Test
    void neutralThemeSupportsSameDeviceOnlyAndRestart() throws Exception {
        useTheme("su-engineering");
        useWalletFlow();
        idpConfig
                .set(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "false")
                .apply();
        navigateDirectlyToWallet();
        flow.getSameDeviceWalletUrl();
        assertThat(page.locator("#oid4vp-qr-code").count()).isZero();
        assertThat(page.locator("#oid4vp-cross-device-status-config").count()).isZero();
        page.getByText("Start again", new com.microsoft.playwright.Page.GetByTextOptions().setExact(true))
                .click();
        page.waitForSelector("#oid4vp-open-wallet");
        assertThat(page.locator("#username, #password").count()).isZero();
    }

    @Test
    void neutralThemeKeepsInheritedLoginValidation() throws Exception {
        useTheme("su-engineering");
        flow.navigateToLoginPage();
        page.locator("#username").fill("admin");
        page.locator("#password").fill("incorrect-demo-password");
        page.locator("#kc-login").click();
        page.waitForSelector("#input-error");
        assertThat(page.locator("#input-error").textContent()).contains("Invalid username or password");
        assertThat(page.locator(".su-form-footer").textContent()).contains("su.engineering");
    }
}
