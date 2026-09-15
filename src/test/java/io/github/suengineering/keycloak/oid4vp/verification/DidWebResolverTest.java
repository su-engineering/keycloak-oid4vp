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
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

class DidWebResolverTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private KeycloakSession session;
    private DidWebResolver resolver;
    private ECKey testKey;
    private ECKey testKey2;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(DidWebResolverTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        session = mock(KeycloakSession.class);
        resolver = new DidWebResolver(session, 3600);
        testKey = new ECKeyGenerator(Curve.P_256).generate();
        testKey2 = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Nested
    class SupportsMethod {

        @Test
        void supports_didWeb_returnsTrue() {
            assertThat(resolver.supports("did:web:example.com")).isTrue();
        }

        @Test
        void supports_didWebWithPath_returnsTrue() {
            assertThat(resolver.supports("did:web:example.com:path:to:resource"))
                    .isTrue();
        }

        @Test
        void supports_didWebUpperCase_returnsTrue() {
            assertThat(resolver.supports("DID:WEB:example.com")).isTrue();
        }

        @Test
        void supports_didKey_returnsFalse() {
            assertThat(resolver.supports("did:key:z6Mkfriq1Lz5WZG65eMungWKEQyDqF7rE13qn"))
                    .isFalse();
        }

        @Test
        void supports_didJwk_returnsFalse() {
            assertThat(resolver.supports("did:jwk:eyJrdHkiOiJFQ1MiLHJ0eSI6Ik9LUCJ9"))
                    .isFalse();
        }

        @Test
        void supports_didWebbCaseVariation_returnsTrue() {
            assertThat(resolver.supports("did:Web:example.com")).isTrue();
        }

        @Test
        void supports_null_returnsFalse() {
            assertThat(resolver.supports(null)).isFalse();
        }

        @Test
        void supports_emptyString_returnsFalse() {
            assertThat(resolver.supports("")).isFalse();
        }

        @Test
        void supports_randomString_returnsFalse() {
            assertThat(resolver.supports("not-a-did")).isFalse();
        }
    }

    @Nested
    class UrlTransformation {

        @Test
        void transformToUrl_simpleDomain() throws Exception {
            String url = invokeTransformToUrl("example.com");
            assertThat(url).isEqualTo("https://example.com/.well-known/did.json");
        }

        @Test
        void transformToUrl_domainWithPort() throws Exception {
            String url = invokeTransformToUrl("example.com:8080");
            assertThat(url).isEqualTo("https://example.com/8080/.well-known/did.json");
        }

        @Test
        void transformToUrl_domainWithPath() throws Exception {
            String url = invokeTransformToUrl("example.com:path:to:resource");
            assertThat(url).isEqualTo("https://example.com/path/to/resource/.well-known/did.json");
        }

        @Test
        void transformToUrl_domainWithMultiplePathSegments() throws Exception {
            String url = invokeTransformToUrl("example.com:a:b:c:d");
            assertThat(url).isEqualTo("https://example.com/a/b/c/d/.well-known/did.json");
        }

        private String invokeTransformToUrl(String didWebId) throws Exception {
            var method = DidWebResolver.class.getDeclaredMethod("transformToUrl", String.class);
            method.setAccessible(true);
            return (String) method.invoke(resolver, didWebId);
        }
    }

    @Nested
    class ResolveMethod {

        @Test
        void resolve_nonDidWeb_throwsIllegalArgumentException() {
            assertThatThrownBy(() -> resolver.resolve("did:key:abc", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("did:web");
        }

        @Test
        void resolve_emptyDidWebId_throwsDidResolutionException() {
            assertThatThrownBy(() -> resolver.resolve("did:web:", null))
                    .isInstanceOf(DidResolutionException.class)
                    .hasMessageContaining("missing identifier");
        }

        @Test
        void resolve_httpUrl_wouldBeRejectedBySecurityCheck() {
            String nonHttpsUrl = "http://example.com/.well-known/did.json";
            assertThat(nonHttpsUrl.toLowerCase().startsWith("https://")).isFalse();
        }
    }

    @Nested
    class HttpsSecurityCheck {

        @Test
        void securityCheck_rejectsNonHttpsUrls() {
            String nonHttpsUrl = "http://example.com/.well-known/did.json";
            assertThat(nonHttpsUrl.toLowerCase().startsWith("https://")).isFalse();
        }

        @Test
        void securityCheck_acceptsHttpsUrls() {
            String httpsUrl = "https://example.com/.well-known/did.json";
            assertThat(httpsUrl.toLowerCase().startsWith("https://")).isTrue();
        }
    }

    @Nested
    class HttpFetchErrorHandling {

        @Test
        void resolve_httpError404_throwsDidResolutionException() throws Exception {
            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenThrow(new RuntimeException("HTTP 404"));

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                assertThatThrownBy(() -> resolver.resolve("did:web:example.com", null))
                        .isInstanceOf(DidResolutionException.class)
                        .hasMessageContaining("Failed to fetch DID document");
            }
        }

        @Test
        void resolve_httpError500_throwsDidResolutionException() throws Exception {
            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenThrow(new RuntimeException("HTTP 500"));

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                assertThatThrownBy(() -> resolver.resolve("did:web:example.com", null))
                        .isInstanceOf(DidResolutionException.class)
                        .hasMessageContaining("Failed to fetch DID document");
            }
        }

        @Test
        void resolve_invalidJson_throwsDidResolutionException() throws Exception {
            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn("not valid json {{{");

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                assertThatThrownBy(() -> resolver.resolve("did:web:example.com", null))
                        .isInstanceOf(DidResolutionException.class)
                        .hasMessageContaining("Failed to parse DID document");
            }
        }

        @Test
        void resolve_missingVerificationMethod_returnsEmptyList() throws Exception {
            String didDocJson = """
                {
                    "id": "did:web:example.com"
                }
                """;

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                List<SignatureVerifierContext> result = resolver.resolve("did:web:example.com", null);

                assertThat(result).isEmpty();
            }
        }
    }

    @Nested
    class SuccessfulResolution {

        @Test
        void resolve_validDidDocument_returnsVerifiers() throws Exception {
            Map<String, Object> publicKeyJwk = testKey.toPublicJWK().toJSONObject();
            String didDocJson = buildDidDocJson("did:web:example.com", "did:web:example.com#key-1", publicKeyJwk);

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                List<SignatureVerifierContext> result = resolver.resolve("did:web:example.com", null);

                assertThat(result).isNotEmpty();
            }
        }

        @Test
        void resolve_multipleVerificationMethods_returnsAllVerifiers() throws Exception {
            Map<String, Object> publicKeyJwk1 = testKey.toPublicJWK().toJSONObject();
            Map<String, Object> publicKeyJwk2 = testKey2.toPublicJWK().toJSONObject();
            String didDocJson = buildDidDocJsonWithMultipleKeys(
                    "did:web:example.com",
                    "did:web:example.com#key-1",
                    publicKeyJwk1,
                    "did:web:example.com#key-2",
                    publicKeyJwk2);

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                List<SignatureVerifierContext> result = resolver.resolve("did:web:example.com", null);

                assertThat(result).hasSize(2);
            }
        }

        @Test
        void resolve_verificationMethodWithoutPublicKeyJwk_skipsMethod() throws Exception {
            String didDocJson = """
                {
                    "id": "did:web:example.com",
                    "verificationMethod": [{
                        "id": "did:web:example.com#key-1",
                        "type": "Ed25519VerificationKey2020",
                        "controller": "did:web:example.com"
                    }]
                }
                """;

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                List<SignatureVerifierContext> result = resolver.resolve("did:web:example.com", null);

                assertThat(result).isEmpty();
            }
        }

        @Test
        void resolve_verificationMethodWithEmptyPublicKeyJwk_skipsMethod() throws Exception {
            String didDocJson = """
                {
                    "id": "did:web:example.com",
                    "verificationMethod": [{
                        "id": "did:web:example.com#key-1",
                        "type": "JsonWebKey2020",
                        "controller": "did:web:example.com",
                        "publicKeyJwk": {}
                    }]
                }
                """;

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                List<SignatureVerifierContext> result = resolver.resolve("did:web:example.com", null);

                assertThat(result).isEmpty();
            }
        }

        private String buildDidDocJson(String did, String keyId, Map<String, Object> publicKeyJwk) throws Exception {
            return """
                {
                    "id": "%s",
                    "verificationMethod": [{
                        "id": "%s",
                        "type": "JsonWebKey2020",
                        "controller": "%s",
                        "publicKeyJwk": %s
                    }]
                }
                """.formatted(did, keyId, did, MAPPER.writeValueAsString(publicKeyJwk));
        }

        private String buildDidDocJsonWithMultipleKeys(
                String did,
                String keyId1,
                Map<String, Object> publicKeyJwk1,
                String keyId2,
                Map<String, Object> publicKeyJwk2)
                throws Exception {
            return """
                {
                    "id": "%s",
                    "verificationMethod": [
                        {
                            "id": "%s",
                            "type": "JsonWebKey2020",
                            "controller": "%s",
                            "publicKeyJwk": %s
                        },
                        {
                            "id": "%s",
                            "type": "JsonWebKey2020",
                            "controller": "%s",
                            "publicKeyJwk": %s
                        }
                    ]
                }
                """.formatted(
                            did,
                            keyId1,
                            did,
                            MAPPER.writeValueAsString(publicKeyJwk1),
                            keyId2,
                            did,
                            MAPPER.writeValueAsString(publicKeyJwk2));
        }
    }

    @Nested
    class CacheBehavior {

        @Test
        void resolve_firstCall_fetchesFromHttp() throws Exception {
            Map<String, Object> publicKeyJwk = testKey.toPublicJWK().toJSONObject();
            String didDocJson = buildDidDocJson("did:web:example.com", "did:web:example.com#key-1", publicKeyJwk);

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                resolver.resolve("did:web:example.com", null);

                mockedStatic.verify(() -> SimpleHttp.doGet(anyString(), eq(session)), times(1));
            }
        }

        @Test
        void resolve_secondCall_returnsCachedResult() throws Exception {
            Map<String, Object> publicKeyJwk = testKey.toPublicJWK().toJSONObject();
            String didDocJson = buildDidDocJson("did:web:example.com", "did:web:example.com#key-1", publicKeyJwk);

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                List<SignatureVerifierContext> firstResult = resolver.resolve("did:web:example.com", null);
                List<SignatureVerifierContext> secondResult = resolver.resolve("did:web:example.com", null);

                mockedStatic.verify(() -> SimpleHttp.doGet(anyString(), eq(session)), times(1));
                assertThat(firstResult).hasSize(secondResult.size());
            }
        }

        @Test
        void resolve_differentDids_fetchesSeparately() throws Exception {
            Map<String, Object> publicKeyJwk1 = testKey.toPublicJWK().toJSONObject();
            Map<String, Object> publicKeyJwk2 = testKey2.toPublicJWK().toJSONObject();
            String didDocJson1 = buildDidDocJson("did:web:example.com", "did:web:example.com#key-1", publicKeyJwk1);
            String didDocJson2 = buildDidDocJson("did:web:other.com", "did:web:other.com#key-1", publicKeyJwk2);

            int[] callCount = {0};
            String[] responses = {didDocJson1, didDocJson2};

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenAnswer(invocation -> responses[callCount[0]++]);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                resolver.resolve("did:web:example.com", null);
                resolver.resolve("did:web:other.com", null);

                mockedStatic.verify(() -> SimpleHttp.doGet(anyString(), eq(session)), times(2));
            }
        }

        private String buildDidDocJson(String did, String keyId, Map<String, Object> publicKeyJwk) throws Exception {
            return """
                {
                    "id": "%s",
                    "verificationMethod": [{
                        "id": "%s",
                        "type": "JsonWebKey2020",
                        "controller": "%s",
                        "publicKeyJwk": %s
                    }]
                }
                """.formatted(did, keyId, did, MAPPER.writeValueAsString(publicKeyJwk));
        }
    }

    @Nested
    class PercentEncoding {

        @Test
        void resolve_percentEncodedDid_resolvesCorrectly() throws Exception {
            Map<String, Object> publicKeyJwk = testKey.toPublicJWK().toJSONObject();
            String didDocJson = buildDidDocJson("did:web:example.com", "did:web:example.com#key-1", publicKeyJwk);

            SimpleHttp mockHttp = mock(SimpleHttp.class);
            when(mockHttp.header(anyString(), anyString())).thenReturn(mockHttp);
            when(mockHttp.asString()).thenReturn(didDocJson);

            try (var mockedStatic = mockStatic(SimpleHttp.class)) {
                mockedStatic
                        .when(() -> SimpleHttp.doGet(anyString(), any(KeycloakSession.class)))
                        .thenReturn(mockHttp);

                List<SignatureVerifierContext> result = resolver.resolve("did:web:example.com", null);

                assertThat(result).isNotEmpty();
            }
        }

        private String buildDidDocJson(String did, String keyId, Map<String, Object> publicKeyJwk) throws Exception {
            return """
                {
                    "id": "%s",
                    "verificationMethod": [{
                        "id": "%s",
                        "type": "JsonWebKey2020",
                        "controller": "%s",
                        "publicKeyJwk": %s
                    }]
                }
                """.formatted(did, keyId, did, MAPPER.writeValueAsString(publicKeyJwk));
        }
    }
}
