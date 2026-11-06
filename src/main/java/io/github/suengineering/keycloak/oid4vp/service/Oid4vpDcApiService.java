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

import static io.github.suengineering.keycloak.oid4vp.domain.Oid4vpConstants.FLOW_DC_API;
import static io.github.suengineering.keycloak.oid4vp.domain.Oid4vpConstants.RESPONSE;
import static io.github.suengineering.keycloak.oid4vp.domain.Oid4vpConstants.VP_TOKEN;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProvider;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import io.github.suengineering.keycloak.oid4vp.domain.DecryptedResponse;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpJwk;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpResponseMode;
import io.github.suengineering.keycloak.oid4vp.domain.PreparedDcqlQuery;
import io.github.suengineering.keycloak.oid4vp.domain.RequestObjectParams;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpResponseDecryptor;
import io.github.suengineering.keycloak.oid4vp.util.Oid4vpSigningKeyParser;
import io.github.suengineering.keycloak.oid4vp.verification.IsoMdocDcApi;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Runs the OID4VP flow over the W3C Digital Credentials API (OID4VP 1.0 Appendix A).
 *
 * <p>Unlike the redirect flows, the wallet never talks to Keycloak: the login page calls
 * {@code navigator.credentials.get()} and hands the result back. Both calls therefore come from the
 * browser that owns the authentication session, and each is checked against it. The response is
 * bound to the Keycloak origin (SD-JWT audience {@code origin:<origin>}, mdoc
 * {@code OpenID4VPDCAPIHandover}) and to a fresh nonce per request.
 */
public class Oid4vpDcApiService {

    /** Upper bound for the JSON the page posts back; a presentation response is far smaller. */
    static final int MAX_RESPONSE_CHARS = 3 * 1024 * 1024;

    private static final Logger LOG = Logger.getLogger(Oid4vpDcApiService.class);

    private static final ObjectMapper STRICT_JSON = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    private final KeycloakSession session;
    private final Oid4vpIdentityProvider provider;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final Oid4vpAuthSessionResolver authSessionResolver;
    private final Oid4vpResponseDecryptor responseDecryptor;

    public Oid4vpDcApiService(
            KeycloakSession session,
            Oid4vpIdentityProvider provider,
            Oid4vpRequestObjectStore requestObjectStore,
            Oid4vpAuthSessionResolver authSessionResolver,
            Oid4vpResponseDecryptor responseDecryptor) {
        this.session = session;
        this.provider = provider;
        this.requestObjectStore = requestObjectStore;
        this.authSessionResolver = authSessionResolver;
        this.responseDecryptor = responseDecryptor;
    }

    /** A request the page passes to {@code navigator.credentials.get()}, plus the state to post back. */
    public record DcApiRequest(String state, List<Map<String, Object>> requests) {}

    /** The outcome of a posted response: a verified identity, or the wallet's own error. */
    public record DcApiResult(
            AuthenticationSessionModel authSession,
            Oid4vpRequestObjectStore.RequestContextEntry requestContext,
            BrokeredIdentityContext identity,
            String walletError,
            String walletErrorDescription) {}

    /** Thrown when the request handle, browser session, or state do not match a live DC API flow. */
    public static class FlowMismatchException extends RuntimeException {
        private final String error;

        FlowMismatchException(String error, String description) {
            super(description);
            this.error = error;
        }

        public String error() {
            return error;
        }
    }

    public DcApiRequest createRequest(String requestHandle) {
        Oid4vpRequestObjectStore.FlowContextEntry flow = requireFlow(requestHandle);
        requireBrowserSession(flow);

        Oid4vpIdentityProviderConfig config = provider.getConfig();
        Oid4vpResponseMode responseMode = config.getResolvedResponseMode().forDcApi();
        PreparedDcqlQuery dcql = provider.prepareDcqlQueryFromConfig();
        String origin = keycloakOrigin();
        String state = buildState(flow.tabId());
        String nonce = UUID.randomUUID().toString();

        String encryptionKeyJson = null;
        String encryptionJwkThumbprint = null;
        if (responseMode.requiresEncryption()) {
            Oid4vpJwk key = provider.getRedirectFlowService().createResponseEncryptionKey();
            encryptionKeyJson = key.toJson();
            encryptionJwkThumbprint = Oid4vpRequestObjectStore.computeEncryptionJwkThumbprint(encryptionKeyJson);
        }

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = new Oid4vpRequestObjectStore.RequestContextEntry(
                requestHandle,
                flow.rootSessionId(),
                flow.tabId(),
                state,
                flow.effectiveClientId(),
                null,
                FLOW_DC_API,
                nonce,
                encryptionKeyJson,
                encryptionJwkThumbprint,
                dcql.configuredCredentialTypes(),
                dcql.dcqlQuery(),
                config.getIdentityCredentialId(),
                origin,
                null,
                null);

        Map<String, Object> request = provider.getRedirectFlowService()
                .buildDcApiRequest(
                        new RequestObjectParams(
                                dcql.dcqlQuery(),
                                config.getVerifierInfo(),
                                flow.effectiveClientId(),
                                config.getClientIdScheme(),
                                null,
                                state,
                                nonce,
                                config.getX509CertificatePem(),
                                config.getX509SigningKeyJwk(),
                                encryptionKeyJson,
                                null,
                                responseMode,
                                false,
                                config.isEnforceHaip()),
                        origin);
        List<Map<String, Object>> requests = new ArrayList<>();
        requests.add(request);

        // Offer ISO/IEC 18013-7 Annex C next to OpenID4VP; the browser or wallet picks one.
        if (config.isDcApiIsoMdocEnabled()
                && !IsoMdocDcApi.docQueries(dcql.dcqlQuery()).isEmpty()) {
            IsoMdocDcApi.PreparedRequest iso = IsoMdocDcApi.prepare(dcql.dcqlQuery(), origin, readerKey(config));
            requestContext = new Oid4vpRequestObjectStore.RequestContextEntry(
                    requestContext.requestHandle(),
                    requestContext.rootSessionId(),
                    requestContext.tabId(),
                    requestContext.state(),
                    requestContext.effectiveClientId(),
                    null,
                    FLOW_DC_API,
                    requestContext.nonce(),
                    requestContext.encryptionKeyJson(),
                    requestContext.encryptionJwkThumbprint(),
                    requestContext.configuredCredentialTypes(),
                    requestContext.dcqlQuery(),
                    requestContext.identityCredentialId(),
                    origin,
                    iso.encryptionInfo(),
                    iso.recipientKeyJson());
            Map<String, Object> isoRequest = new LinkedHashMap<>();
            isoRequest.put("protocol", IsoMdocDcApi.PROTOCOL);
            isoRequest.put(
                    "data", Map.of("deviceRequest", iso.deviceRequest(), "encryptionInfo", iso.encryptionInfo()));
            requests.add(isoRequest);
        }

        requestObjectStore.storeRequestContext(session, requestContext);
        return new DcApiRequest(state, requests);
    }

    /**
     * The verifier key that signs ISO requests ({@code readerAuthAll}), or {@code null} for an
     * unsigned request. Apple Wallet only answers signed requests.
     */
    private static IsoMdocDcApi.ReaderKey readerKey(Oid4vpIdentityProviderConfig config) {
        if (StringUtil.isBlank(config.getX509SigningKeyJwk()) || StringUtil.isBlank(config.getX509CertificatePem())) {
            return null;
        }
        try {
            KeyWrapper key = Oid4vpSigningKeyParser.parse(config.getX509SigningKeyJwk());
            List<X509Certificate> chain = key.getCertificateChain() != null
                            && !key.getCertificateChain().isEmpty()
                    ? key.getCertificateChain()
                    : key.getCertificate() != null ? List.of(key.getCertificate()) : List.of();
            if (chain.isEmpty()
                    || !(key.getPrivateKey() instanceof ECPrivateKey ecKey)
                    || ecKey.getParams().getCurve().getField().getFieldSize() != 256) {
                LOG.debugf(
                        "ISO mdoc request stays unsigned: reader authentication needs a P-256 key with a certificate");
                return null;
            }
            return new IsoMdocDcApi.ReaderKey((java.security.PrivateKey) key.getPrivateKey(), chain);
        } catch (Exception e) {
            LOG.warnf("ISO mdoc request stays unsigned: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Verifies the {@code data} of the credential the browser returned. Throws
     * {@link FlowMismatchException} when the post does not belong to a live flow of this browser,
     * and {@link IdentityBrokerException} when the presentation does not verify.
     */
    public DcApiResult handleResponse(String requestHandle, String state, String responseData) {
        return handleResponse(requestHandle, state, null, responseData);
    }

    /** As {@link #handleResponse(String, String, String)}, for the protocol the browser reports. */
    public DcApiResult handleResponse(String requestHandle, String state, String protocol, String responseData) {
        Oid4vpRequestObjectStore.FlowContextEntry flow = requireFlow(requestHandle);
        AuthenticationSessionModel authSession = requireBrowserSession(flow);

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestObjectStore.resolveByState(session, state);
        if (requestContext == null
                || !FLOW_DC_API.equals(requestContext.flow())
                || !requestHandle.equals(requestContext.requestHandle())
                || StringUtil.isBlank(requestContext.origin())) {
            throw new FlowMismatchException("session_expired", "Request expired. Please try again.");
        }

        JsonNode data = parseResponseData(responseData);
        String walletError = text(data, OAuth2Constants.ERROR);
        if (walletError != null) {
            return new DcApiResult(
                    authSession, requestContext, null, walletError, text(data, OAuth2Constants.ERROR_DESCRIPTION));
        }

        boolean isoMdoc = IsoMdocDcApi.PROTOCOL.equals(protocol);
        if (isoMdoc && StringUtil.isBlank(requestContext.isoEncryptionInfo())) {
            throw new IdentityBrokerException("No org-iso-mdoc request was made for this flow.");
        }
        Oid4vpRequestObjectStore.RequestContextEntry verificationContext =
                isoMdoc ? requestContext : requestContext.withoutIsoMdoc();
        String vpToken = isoMdoc ? extractIsoVpToken(data, requestContext) : extractVpToken(data, requestContext);
        BrokeredIdentityContext identity =
                provider.getCallbackProcessor().process(verificationContext, vpToken, null, null);
        // The nonce is single-use: a verified response cannot be posted a second time.
        requestObjectStore.removeRequestContext(session, requestContext.state());
        return new DcApiResult(authSession, requestContext, identity, null, null);
    }

    private String extractIsoVpToken(JsonNode data, Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        JsonNode response = data.get(RESPONSE);
        if (response == null || !response.isTextual()) {
            throw new IdentityBrokerException("Missing org-iso-mdoc response");
        }
        try {
            Map<String, List<String>> presentations = IsoMdocDcApi.openResponse(
                    response.textValue(),
                    new IsoMdocDcApi.PreparedRequest(
                            null, requestContext.isoEncryptionInfo(), requestContext.isoRecipientKeyJson()),
                    requestContext.origin(),
                    IsoMdocDcApi.docQueries(requestContext.dcqlQuery()));
            return STRICT_JSON.writeValueAsString(presentations);
        } catch (IllegalArgumentException e) {
            throw new IdentityBrokerException(e.getMessage(), e);
        } catch (Exception e) {
            throw new IdentityBrokerException("Unreadable org-iso-mdoc response", e);
        }
    }

    private String extractVpToken(JsonNode data, Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        JsonNode encrypted = data.get(RESPONSE);
        boolean encryptionExpected = StringUtil.isNotBlank(requestContext.encryptionKeyJson());
        if (encrypted != null) {
            if (!encryptionExpected || !encrypted.isTextual()) {
                throw new IdentityBrokerException("Unexpected encrypted response for this request.");
            }
            DecryptedResponse decrypted;
            try {
                decrypted = responseDecryptor.decrypt(encrypted.textValue(), parseKey(requestContext));
            } catch (IllegalStateException e) {
                throw new IdentityBrokerException("Encrypted response could not be decrypted.", e);
            }
            if (StringUtil.isNotBlank(decrypted.error())) {
                throw new IdentityBrokerException("Wallet returned an error: " + decrypted.error());
            }
            return decrypted.vpToken();
        }
        if (encryptionExpected) {
            throw new IdentityBrokerException(
                    "Encrypted response expected (dc_api.jwt) but received unencrypted vp_token.");
        }
        JsonNode vpToken = data.get(VP_TOKEN);
        if (vpToken == null || vpToken.isNull()) {
            throw new IdentityBrokerException("Missing vp_token");
        }
        return vpToken.isTextual() ? vpToken.textValue() : vpToken.toString();
    }

    private static Oid4vpJwk parseKey(Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        try {
            return Oid4vpJwk.parse(requestContext.encryptionKeyJson());
        } catch (Exception e) {
            throw new IdentityBrokerException("Stored response decryption key is unreadable.", e);
        }
    }

    private static JsonNode parseResponseData(String responseData) {
        if (StringUtil.isBlank(responseData) || responseData.length() > MAX_RESPONSE_CHARS) {
            throw new IdentityBrokerException("Missing or oversized Digital Credentials API response.");
        }
        try {
            JsonNode node = STRICT_JSON.readTree(responseData);
            if (node == null || !node.isObject()) {
                throw new IdentityBrokerException("Digital Credentials API response must be a JSON object.");
            }
            return node;
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Digital Credentials API response is not valid JSON.", e);
        }
    }

    private static String text(JsonNode data, String field) {
        JsonNode value = data.get(field);
        return value != null && value.isTextual() && !value.textValue().isBlank() ? value.textValue() : null;
    }

    private Oid4vpRequestObjectStore.FlowContextEntry requireFlow(String requestHandle) {
        if (StringUtil.isBlank(requestHandle)) {
            throw new FlowMismatchException("invalid_request", "Missing request handle");
        }
        Oid4vpRequestObjectStore.FlowContextEntry flow = requestObjectStore.resolveFlowHandle(session, requestHandle);
        if (flow == null || !FLOW_DC_API.equals(flow.flow())) {
            throw new FlowMismatchException("session_expired", "Request handle not found or expired");
        }
        return flow;
    }

    /** Both DC API calls come from the login page, so they must carry that page's browser session. */
    private AuthenticationSessionModel requireBrowserSession(Oid4vpRequestObjectStore.FlowContextEntry flow) {
        AuthenticationSessionModel expected =
                authSessionResolver.resolveFromTokenEntry(flow.rootSessionId(), flow.tabId());
        if (expected == null) {
            throw new FlowMismatchException(
                    "session_expired", "Authentication session expired. Please restart the login flow.");
        }
        AuthenticationSessionModel current = authSessionResolver.resolveCurrentBrowserSession(expected);
        if (!authSessionResolver.sameAuthenticationSession(current, expected)) {
            throw new FlowMismatchException(
                    "session_expired", "Authentication session does not match the current browser session.");
        }
        return current;
    }

    /** The origin of the Keycloak front end, which serves the login page that calls the browser API. */
    String keycloakOrigin() {
        return originOf(session.getContext().getUri().getBaseUri());
    }

    static String originOf(URI uri) {
        String scheme = uri.getScheme().toLowerCase(java.util.Locale.ROOT);
        String host = uri.getHost().toLowerCase(java.util.Locale.ROOT);
        int port = uri.getPort();
        boolean defaultPort =
                port == -1 || ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
        if (host.contains(":") && !host.startsWith("[")) {
            host = "[" + host + "]";
        }
        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }

    private static String buildState(String tabId) {
        return StringUtil.isBlank(tabId) ? UUID.randomUUID().toString() : tabId + "." + UUID.randomUUID();
    }

    /** Serializes the request for the page: {@code {state, requests: [{protocol, data}, ...]}}. */
    public static Map<String, Object> toPageJson(DcApiRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put(OAuth2Constants.STATE, request.state());
        body.put("requests", request.requests());
        return body;
    }
}
