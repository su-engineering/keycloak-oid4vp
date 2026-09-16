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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.suengineering.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import io.github.suengineering.keycloak.oid4vp.domain.MdocVerificationResult;
import io.github.suengineering.keycloak.oid4vp.domain.PresentationType;
import io.github.suengineering.keycloak.oid4vp.domain.SdJwtVerificationResult;
import io.github.suengineering.keycloak.oid4vp.domain.VerifiedCredential;
import io.github.suengineering.keycloak.oid4vp.domain.VpTokenResult;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/**
 * Top-level processor for VP tokens received from wallets.
 *
 * <p>Handles SD-JWT and mDoc presentations grouped by DCQL query ID,
 * signature verification (delegated to {@link SdJwtVerifier} / {@link MdocVerifier}),
 * trust list validation, and revocation checking (via {@link StatusListVerifier}).
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7">OID4VP 1.0 §7 — VP Token</a>
 */
public class VpTokenProcessor {

    private static final Logger LOG = Logger.getLogger(VpTokenProcessor.class);

    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;
    private final StatusListVerifier statusListVerifier;
    private final ObjectMapper objectMapper;
    private final TrustListProvider trustListProvider;
    private final String expectedTrustListLoTEType;
    private final DidResolver didResolver;

    public record Config(
            KeycloakSession session,
            String trustListUrl,
            Duration statusListMaxCacheTtl,
            Duration trustListMaxCacheTtl,
            Duration issuerMetadataMaxCacheTtl,
            boolean strictX5cVerification,
            int clockSkewSeconds,
            int kbJwtMaxAgeSeconds,
            List<X509Certificate> trustListSigningCerts,
            Duration trustListMaxStaleAge,
            String expectedTrustListLoTEType,
            DidResolver didResolver) {}

    public record Request(
            String vpToken,
            String clientId,
            String expectedNonce,
            String alternateResponseUri,
            String mdocGeneratedNonce,
            String encryptionJwkThumbprint,
            String dcqlQuery) {}

    public VpTokenProcessor(ObjectMapper objectMapper, Config config) {
        this.sdJwtVerifier = new SdJwtVerifier(
                config.clockSkewSeconds(),
                config.kbJwtMaxAgeSeconds(),
                config.didResolver(),
                new JwtVcIssuerMetadataResolver(config.session(), config.issuerMetadataMaxCacheTtl()),
                config.strictX5cVerification());
        this.mdocVerifier = new MdocVerifier();
        this.trustListProvider = new TrustListProvider(
                config.session(),
                config.trustListUrl(),
                config.trustListMaxCacheTtl(),
                config.trustListMaxStaleAge(),
                config.trustListSigningCerts());
        this.statusListVerifier =
                new StatusListVerifier(config.session(), this.trustListProvider, config.statusListMaxCacheTtl());
        this.objectMapper = objectMapper;
        this.expectedTrustListLoTEType = config.expectedTrustListLoTEType();
        this.didResolver = config.didResolver();
    }

    public VpTokenProcessor(ObjectMapper objectMapper, StatusListVerifier statusListVerifier) {
        this(objectMapper, statusListVerifier, null);
    }

    public VpTokenProcessor(
            ObjectMapper objectMapper, StatusListVerifier statusListVerifier, TrustListProvider trustListProvider) {
        this.sdJwtVerifier = new SdJwtVerifier(
                Oid4vpIdentityProviderConfig.DEFAULT_CLOCK_SKEW_SECONDS,
                Oid4vpIdentityProviderConfig.DEFAULT_KB_JWT_MAX_AGE_SECONDS);
        this.mdocVerifier = new MdocVerifier();
        this.statusListVerifier = statusListVerifier;
        this.trustListProvider = trustListProvider;
        this.objectMapper = objectMapper;
        this.expectedTrustListLoTEType = null;
        this.didResolver = null;
    }

    /**
     * Processes a VP token: detects format, verifies credentials, checks revocation status.
     *
     * @param request the wallet response plus verification context
     */
    public VpTokenResult process(Request request) {
        List<X509Certificate> trustedCerts =
                trustListProvider != null ? trustListProvider.getIssuanceCertificates() : List.of();
        validateTrustListLoTEType();
        LOG.debugf("Trust list provides %d trusted keys", trustedCerts.size());

        try {
            DcqlResponseValidator dcql = new DcqlResponseValidator(request.dcqlQuery());
            Map<String, List<String>> presentations = parsePresentations(request.vpToken(), dcql);
            dcql.validateSelection(presentations);
            Map<String, List<VerifiedCredential>> verified = new LinkedHashMap<>();
            // Request order, never wallet-controlled JSON object order, determines the default identity.
            for (String id : dcql.credentialIds()) {
                if (!presentations.containsKey(id)) continue;
                List<VerifiedCredential> credentials = new ArrayList<>();
                for (String presentation : presentations.get(id)) {
                    VerifiedCredential credential = verifyCredential(
                            id,
                            presentation,
                            request.clientId(),
                            request.expectedNonce(),
                            trustedCerts,
                            request.alternateResponseUri(),
                            request.mdocGeneratedNonce(),
                            request.encryptionJwkThumbprint());
                    if (credential == null) throw new IdentityBrokerException("Unsupported VP token format for " + id);
                    dcql.validateCredential(credential);
                    credentials.add(credential);
                }
                verified.put(id, credentials);
            }
            return new VpTokenResult(verified);
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("VP token processing failed: " + e.getMessage(), e);
        }
    }

    private Map<String, List<String>> parsePresentations(String vpToken, DcqlResponseValidator dcql) throws Exception {
        if (StringUtil.isBlank(vpToken)) throw new IdentityBrokerException("Missing vp_token");
        Map<String, List<String>> result = new LinkedHashMap<>();
        if (!vpToken.stripLeading().startsWith("{")) {
            // Compatibility with older wallets is safe only when the query ID is unambiguous.
            if (dcql.credentialIds().size() != 1) {
                throw new IdentityBrokerException("Multiple credential queries require a JSON vp_token object");
            }
            result.put(dcql.credentialIds().get(0), List.of(vpToken));
            return result;
        }
        JsonNode wrapper = objectMapper
                .reader()
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .readTree(vpToken);
        for (var fields = wrapper.fields(); fields.hasNext(); ) {
            var field = fields.next();
            JsonNode values = field.getValue();
            if (!values.isArray() || values.isEmpty()) {
                throw new IdentityBrokerException(
                        "vp_token entry must be a non-empty presentation array: " + field.getKey());
            }
            List<String> tokens = new ArrayList<>();
            for (JsonNode value : values) {
                if (!value.isTextual() || value.textValue().isBlank()) {
                    throw new IdentityBrokerException(
                            "vp_token presentations must be non-empty strings: " + field.getKey());
                }
                tokens.add(value.textValue());
            }
            result.put(field.getKey(), tokens);
        }
        return result;
    }

    private VerifiedCredential verifyCredential(
            String credentialId,
            String credential,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri,
            String mdocGeneratedNonce,
            String encryptionJwkThumbprint) {

        if (sdJwtVerifier.isSdJwt(credential)) {
            SdJwtVerificationResult result =
                    verifySdJwtWithFallback(credential, clientId, expectedNonce, trustedCerts, alternateResponseUri);
            if (StringUtil.isBlank(result.issuer())) {
                throw new IdentityBrokerException("SD-JWT credential has no issuer: " + credentialId);
            }
            statusListVerifier.checkRevocationStatus(result.claims());
            return new VerifiedCredential(
                    credentialId, result.issuer(), result.credentialType(), result.claims(), PresentationType.SD_JWT);
        }

        if (mdocVerifier.isMdoc(credential)) {
            // Use alternateResponseUri as the response_uri for session transcript
            byte[] jwkThumbprintBytes = decodeJwkThumbprint(encryptionJwkThumbprint);
            MdocVerificationResult result = mdocVerifier.verifyWithTrustedCerts(
                    credential,
                    trustedCerts,
                    clientId,
                    expectedNonce,
                    alternateResponseUri,
                    mdocGeneratedNonce,
                    jwkThumbprintBytes);
            statusListVerifier.checkRevocationStatus(result.claims());
            return new VerifiedCredential(credentialId, null, result.docType(), result.claims(), PresentationType.MDOC);
        }

        return null;
    }

    private byte[] decodeJwkThumbprint(String encoded) {
        if (StringUtil.isBlank(encoded)) return null;
        try {
            return Base64.getUrlDecoder().decode(encoded);
        } catch (Exception e) {
            LOG.warnf("Failed to decode JWK thumbprint: %s", e.getMessage());
            return null;
        }
    }

    private void validateTrustListLoTEType() {
        if (trustListProvider == null || StringUtil.isBlank(expectedTrustListLoTEType)) {
            return;
        }
        String actualLoTEType = trustListProvider.getCurrentLoTEType();
        if (StringUtil.isBlank(actualLoTEType)) {
            return;
        }
        if (!expectedTrustListLoTEType.equals(actualLoTEType)) {
            throw new IdentityBrokerException("Trust list LoTE type mismatch: expected " + expectedTrustListLoTEType
                    + " but got " + actualLoTEType);
        }
    }

    // Wallets in the field are inconsistent here: some bind the KB-JWT to client_id, others to
    // response_uri. We try the configured client_id first and then one bounded fallback to the
    // redirect flow's response_uri so interoperability does not depend on a single audience choice.
    private SdJwtVerificationResult verifySdJwtWithFallback(
            String sdJwt,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri) {
        try {
            return sdJwtVerifier.verify(sdJwt, clientId, expectedNonce, trustedCerts);
        } catch (Exception primaryError) {
            if (StringUtil.isNotBlank(alternateResponseUri)) {
                try {
                    LOG.debugf(
                            "Primary verification failed, retrying with alternate audience: %s", alternateResponseUri);
                    return sdJwtVerifier.verify(sdJwt, alternateResponseUri, expectedNonce, trustedCerts);
                } catch (Exception fallbackError) {
                    LOG.warnf("Fallback verification also failed: %s", fallbackError.getMessage());
                }
            }
            throw primaryError;
        }
    }
}
