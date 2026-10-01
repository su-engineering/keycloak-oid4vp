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
package io.github.suengineering.keycloak.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ThemeResourcesTest {

    @Test
    void oid4vpLoginTemplateUsesDedicatedLayoutWithoutGenericAuthChecker() throws Exception {
        String loginTemplate = loadResource("/theme-resources/templates/login-oid4vp-idp.ftl");
        String layoutTemplate = loadResource("/theme-resources/templates/oid4vp-template.ftl");

        assertThat(loginTemplate).contains("<#import \"oid4vp-template.ftl\" as layout>");
        assertThat(layoutTemplate).doesNotContain("startSessionPolling");
        assertThat(layoutTemplate).doesNotContain("checkAuthSession");
    }

    @Test
    void oid4vpLayoutAvoidsInlineJavaScript() throws Exception {
        String layoutTemplate = loadResource("/theme-resources/templates/oid4vp-template.ftl");

        assertThat(layoutTemplate).doesNotContain("<script type=\"importmap\">");
        assertThat(layoutTemplate).doesNotContain("<script type=\"module\">");
        assertThat(layoutTemplate).doesNotContain("onclick=");
        assertThat(layoutTemplate).doesNotContain("onchange=");
        assertThat(layoutTemplate).doesNotContain("javascript:");
    }

    @Test
    void oid4vpLoginTemplateFiltersCurrentBrokerFromAlternativeMethods() throws Exception {
        String loginTemplate = loadResource("/theme-resources/templates/login-oid4vp-idp.ftl");

        assertThat(loginTemplate).contains("currentBrokerAlias");
        assertThat(loginTemplate).contains("p.alias != (currentBrokerAlias!'')");
        assertThat(loginTemplate).contains("<#if hasAlternativeProvider>");
    }

    @Test
    void oid4vpLoginTemplatesHaveMessagesForEveryReferencedKey() throws Exception {
        for (String base : new String[] {"/theme-resources/", "/theme/openkyc/login/"}) {
            String template = loadResource(
                    base + (base.equals("/theme-resources/") ? "templates/" : "") + "login-oid4vp-idp.ftl");
            java.util.Properties messages = new java.util.Properties();
            messages.load(new java.io.StringReader(loadResource(base + "messages/messages_en.properties")));
            java.util.regex.Matcher matcher =
                    java.util.regex.Pattern.compile("msg\\(\"([^\"]+)\"\\)").matcher(template);
            int count = 0;
            while (matcher.find()) {
                String key = matcher.group(1);
                assertThat(messages.getProperty(key))
                        .as("message %s in %s", key, base)
                        .isNotBlank();
                count++;
            }
            assertThat(count).as("localized messages in %s", base).isPositive();
            assertThat(template).contains("oid4vpOpenWithOpenKYCApp", "oid4vpShowQrToggle");
        }
    }

    @Test
    void openKycTemplatesLoadSelfHostedFonts() throws Exception {
        for (String path : new String[] {
            "/theme-resources/templates/oid4vp-template.ftl",
            "/theme/openkyc/login/oid4vp-template.ftl",
            "/theme/openkyc/login/template.ftl",
            "/theme/openkyc/login/error.ftl",
            "/theme/openkyc/login/resources/css/styles.css"
        }) {
            String resource = loadResource(path);
            assertThat(resource).as(path).doesNotContain("fonts.googleapis.com", "fonts.gstatic.com");
            assertThat(resource).as(path).contains("oid4vp-fonts.css");
        }

        String fontCss = loadResource("/theme-resources/resources/css/oid4vp-fonts.css");
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("url\\(\"\\.\\./(fonts/oid4vp/[^\"]+)\"\\)")
                .matcher(fontCss);
        int count = 0;
        while (matcher.find()) {
            assertThat(getClass().getResource("/theme-resources/resources/" + matcher.group(1)))
                    .as(matcher.group(1))
                    .isNotNull();
            count++;
        }
        assertThat(count).isEqualTo(6);
    }

    @Test
    void loginTemplatesPollCrossDeviceStatusWithoutServerSentEvents() throws Exception {
        for (String path : new String[] {
            "/theme-resources/templates/login-oid4vp-idp.ftl",
            "/theme/openkyc/login/login-oid4vp-idp.ftl",
            "/theme/su-engineering/login/login-oid4vp-idp.ftl"
        }) {
            String template = loadResource(path);
            assertThat(template).as(path).contains("oid4vp-cross-device-status.js", "data-poll-interval-ms");
            assertThat(template).as(path).doesNotContain("oid4vp-cross-device-sse");
        }

        String script = loadResource("/theme-resources/resources/js/oid4vp-cross-device-status.js");
        assertThat(script).contains("fetch(").doesNotContain("EventSource");
        assertThat(getClass().getResource("/theme/openkyc/login/resources/js/oid4vp-cross-device-sse.js"))
                .isNull();
    }

    private String loadResource(String resourcePath) throws IOException {
        try (InputStream input = getClass().getResourceAsStream(resourcePath)) {
            assertThat(input).as("resource %s", resourcePath).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
