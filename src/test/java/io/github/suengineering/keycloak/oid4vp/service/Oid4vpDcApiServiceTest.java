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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProvider;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpJwk;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpResponseMode;
import io.github.suengineering.keycloak.oid4vp.domain.PreparedDcqlQuery;
import io.github.suengineering.keycloak.oid4vp.domain.RequestObjectParams;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpResponseDecryptor;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;

class Oid4vpDcApiServiceTest {

    private static final String HANDLE = "handle-1";
    private static final String STATE = "tab-1.state";
    private static final String ORIGIN = "https://login.example.com:8443";

    private KeycloakSession session;
    private Oid4vpIdentityProviderConfig config;
    private Oid4vpRequestObjectStore store;
    private Oid4vpAuthSessionResolver resolver;
    private Oid4vpRedirectFlowService redirectFlowService;
    private Oid4vpCallbackProcessor callbackProcessor;
    private AuthenticationSessionModel authSession;
    private Oid4vpDcApiService service;
    private Oid4vpIdentityProvider provider;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpDcApiServiceTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("https://LOGIN.example.com:8443/auth/"));
        when(context.getUri()).thenReturn(uriInfo);
        when(session.getContext()).thenReturn(context);

        config = mock(Oid4vpIdentityProviderConfig.class);
        when(config.getResolvedResponseMode()).thenReturn(Oid4vpResponseMode.DIRECT_POST);
        when(config.getClientIdScheme()).thenReturn("plain");
        when(config.getIdentityCredentialId()).thenReturn(null);
        when(config.isDcApiIsoMdocEnabled()).thenReturn(true);

        provider = mock(Oid4vpIdentityProvider.class);
        when(provider.getConfig()).thenReturn(config);
        when(provider.prepareDcqlQueryFromConfig())
                .thenReturn(new PreparedDcqlQuery("{\"credentials\":[]}", List.of("urn:eudi:pid:1")));
        redirectFlowService = mock(Oid4vpRedirectFlowService.class);
        when(redirectFlowService.buildDcApiRequest(any(), anyString()))
                .thenReturn(Map.of("protocol", "openid4vp-v1-unsigned", "data", Map.of()));
        when(provider.getRedirectFlowService()).thenReturn(redirectFlowService);
        callbackProcessor = mock(Oid4vpCallbackProcessor.class);
        when(provider.getCallbackProcessor()).thenReturn(callbackProcessor);

        store = mock(Oid4vpRequestObjectStore.class);
        when(store.resolveFlowHandle(session, HANDLE))
                .thenReturn(new Oid4vpRequestObjectStore.FlowContextEntry(
                        "root-1", "tab-1", "https://kc/realms/test/", null, "dc_api"));

        authSession = mock(AuthenticationSessionModel.class);
        resolver = mock(Oid4vpAuthSessionResolver.class);
        when(resolver.resolveFromTokenEntry("root-1", "tab-1")).thenReturn(authSession);
        when(resolver.resolveCurrentBrowserSession(authSession)).thenReturn(authSession);
        when(resolver.sameAuthenticationSession(authSession, authSession)).thenReturn(true);

        service = new Oid4vpDcApiService(session, provider, store, resolver, new Oid4vpResponseDecryptor());
    }

    @Test
    void createRequest_bindsAFreshContextToTheKeycloakOrigin() {
        Oid4vpDcApiService.DcApiRequest request = service.createRequest(HANDLE);

        ArgumentCaptor<Oid4vpRequestObjectStore.RequestContextEntry> stored =
                ArgumentCaptor.forClass(Oid4vpRequestObjectStore.RequestContextEntry.class);
        verify(store).storeRequestContext(eq(session), stored.capture());
        Oid4vpRequestObjectStore.RequestContextEntry context = stored.getValue();
        assertThat(context.origin()).isEqualTo(ORIGIN);
        assertThat(context.flow()).isEqualTo("dc_api");
        assertThat(context.requestHandle()).isEqualTo(HANDLE);
        assertThat(context.state()).startsWith("tab-1.").isEqualTo(request.state());
        assertThat(context.encryptionKeyJson()).isNull();

        ArgumentCaptor<RequestObjectParams> params = ArgumentCaptor.forClass(RequestObjectParams.class);
        verify(redirectFlowService).buildDcApiRequest(params.capture(), eq(ORIGIN));
        assertThat(params.getValue().responseMode()).isEqualTo(Oid4vpResponseMode.DC_API);
        assertThat(params.getValue().nonce()).isEqualTo(context.nonce());
    }

    @Test
    void createRequest_offersIsoMdocNextToOpenId4vpForAnMdocOnlyQuery() {
        String mdocQuery = "{\"credentials\":[{\"id\":\"mdl\",\"format\":\"mso_mdoc\","
                + "\"meta\":{\"doctype_value\":\"org.iso.18013.5.1.mDL\"},"
                + "\"claims\":[{\"path\":[\"org.iso.18013.5.1\",\"age_over_18\"]}]}]}";
        when(provider.prepareDcqlQueryFromConfig()).thenReturn(new PreparedDcqlQuery(mdocQuery, List.of()));

        Oid4vpDcApiService.DcApiRequest request = service.createRequest(HANDLE);

        assertThat(request.requests())
                .extracting(r -> r.get("protocol"))
                .containsExactly("openid4vp-v1-unsigned", "org-iso-mdoc");
        ArgumentCaptor<Oid4vpRequestObjectStore.RequestContextEntry> stored =
                ArgumentCaptor.forClass(Oid4vpRequestObjectStore.RequestContextEntry.class);
        verify(store).storeRequestContext(eq(session), stored.capture());
        assertThat(stored.getValue().isoEncryptionInfo())
                .isEqualTo(((Map<?, ?>) request.requests().get(1).get("data")).get("encryptionInfo"));
        assertThat(stored.getValue().isoRecipientKeyJson()).contains("\"d\"");
    }

    @Test
    void createRequest_doesNotOfferIsoMdocForSdJwtQueries() {
        assertThat(service.createRequest(HANDLE).requests()).hasSize(1);
    }

    @Test
    void handleResponse_rejectsAnIsoAnswerWhenNoIsoRequestWasMade() {
        givenStoredContext(null);

        assertThatThrownBy(() -> service.handleResponse(HANDLE, STATE, "org-iso-mdoc", "{\"response\":\"x\"}"))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("No org-iso-mdoc request");
    }

    @Test
    void createRequest_encryptedResponseModeUsesDcApiJwtWithAKey() throws Exception {
        when(config.getResolvedResponseMode()).thenReturn(Oid4vpResponseMode.DIRECT_POST_JWT);
        when(redirectFlowService.createResponseEncryptionKey())
                .thenReturn(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"));

        service.createRequest(HANDLE);

        ArgumentCaptor<RequestObjectParams> params = ArgumentCaptor.forClass(RequestObjectParams.class);
        verify(redirectFlowService).buildDcApiRequest(params.capture(), eq(ORIGIN));
        assertThat(params.getValue().responseMode()).isEqualTo(Oid4vpResponseMode.DC_API_JWT);
        assertThat(params.getValue().responseEncryptionKeyJson()).isNotBlank();
    }

    @Test
    void createRequest_rejectsRedirectFlowHandles() {
        when(store.resolveFlowHandle(session, HANDLE))
                .thenReturn(new Oid4vpRequestObjectStore.FlowContextEntry(
                        "root-1", "tab-1", "client", "https://kc/endpoint", "same_device"));

        assertThatThrownBy(() -> service.createRequest(HANDLE))
                .isInstanceOf(Oid4vpDcApiService.FlowMismatchException.class);
        verify(store, never()).storeRequestContext(any(), any());
    }

    @Test
    void createRequest_rejectsAnotherBrowser() {
        when(resolver.sameAuthenticationSession(any(), any())).thenReturn(false);

        assertThatThrownBy(() -> service.createRequest(HANDLE))
                .isInstanceOf(Oid4vpDcApiService.FlowMismatchException.class)
                .hasMessageContaining("browser session");
    }

    @Test
    void handleResponse_returnsTheWalletErrorWithoutVerifying() {
        givenStoredContext(null);

        Oid4vpDcApiService.DcApiResult result = service.handleResponse(HANDLE, STATE, "{\"error\":\"access_denied\"}");

        assertThat(result.walletError()).isEqualTo("access_denied");
        verify(callbackProcessor, never()).process(any(), any(), any(), any());
    }

    @Test
    void handleResponse_verifiesThePlainVpTokenAndConsumesTheRequest() {
        Oid4vpRequestObjectStore.RequestContextEntry context = givenStoredContext(null);
        BrokeredIdentityContext identity = mock(BrokeredIdentityContext.class);
        when(callbackProcessor.process(eq(context), anyString(), isNull(), isNull()))
                .thenReturn(identity);

        Oid4vpDcApiService.DcApiResult result =
                service.handleResponse(HANDLE, STATE, "{\"vp_token\":{\"pid\":[\"eyJ.a.b~\"]}}");

        assertThat(result.identity()).isSameAs(identity);
        verify(callbackProcessor).process(context, "{\"pid\":[\"eyJ.a.b~\"]}", null, null);
        verify(store).removeRequestContext(session, STATE);
    }

    @Test
    void handleResponse_decryptsDcApiJwt() throws Exception {
        Oid4vpJwk key = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
        Oid4vpRequestObjectStore.RequestContextEntry context = givenStoredContext(key.toJson());
        when(callbackProcessor.process(eq(context), anyString(), isNull(), isNull()))
                .thenReturn(mock(BrokeredIdentityContext.class));

        ECKey publicKey = ECKey.parse(key.toPublicJwk().toJson());
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID())
                        .build(),
                new Payload("{\"vp_token\":{\"pid\":[\"token\"]}}"));
        jwe.encrypt(new ECDHEncrypter(publicKey));

        service.handleResponse(HANDLE, STATE, "{\"response\":\"" + jwe.serialize() + "\"}");

        verify(callbackProcessor).process(context, "{\"pid\":[\"token\"]}", null, null);
    }

    @Test
    void handleResponse_rejectsAnUnencryptedResponseWhenEncryptionWasRequested() throws Exception {
        givenStoredContext(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc").toJson());

        assertThatThrownBy(() -> service.handleResponse(HANDLE, STATE, "{\"vp_token\":{\"pid\":[\"x\"]}}"))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Encrypted response expected");
    }

    @Test
    void handleResponse_rejectsAStateFromAnotherHandle() {
        when(store.resolveByState(session, STATE)).thenReturn(contextEntry("other-handle", null));

        assertThatThrownBy(() -> service.handleResponse(HANDLE, STATE, "{\"vp_token\":{}}"))
                .isInstanceOf(Oid4vpDcApiService.FlowMismatchException.class);
    }

    @Test
    void handleResponse_rejectsMalformedJson() {
        givenStoredContext(null);

        assertThatThrownBy(() -> service.handleResponse(HANDLE, STATE, "{\"vp_token\":{},\"vp_token\":{}}"))
                .isInstanceOf(IdentityBrokerException.class);
        assertThatThrownBy(() -> service.handleResponse(HANDLE, STATE, "[]"))
                .isInstanceOf(IdentityBrokerException.class);
    }

    @Test
    void originOf_dropsDefaultPortsAndNormalizesCase() {
        assertThat(Oid4vpDcApiService.originOf(URI.create("HTTPS://Login.Example.com:443/auth/")))
                .isEqualTo("https://login.example.com");
        assertThat(Oid4vpDcApiService.originOf(URI.create("http://localhost:8080/")))
                .isEqualTo("http://localhost:8080");
    }

    private Oid4vpRequestObjectStore.RequestContextEntry givenStoredContext(String encryptionKeyJson) {
        Oid4vpRequestObjectStore.RequestContextEntry context = contextEntry(HANDLE, encryptionKeyJson);
        when(store.resolveByState(session, STATE)).thenReturn(context);
        return context;
    }

    private static Oid4vpRequestObjectStore.RequestContextEntry contextEntry(String handle, String encryptionKeyJson) {
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                handle,
                "root-1",
                "tab-1",
                STATE,
                "https://kc/realms/test/",
                null,
                "dc_api",
                "nonce-1",
                encryptionKeyJson,
                null,
                List.of(),
                "{\"credentials\":[]}",
                null,
                ORIGIN,
                null,
                null);
    }
}
