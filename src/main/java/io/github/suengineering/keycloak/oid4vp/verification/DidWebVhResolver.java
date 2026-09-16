/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.decentralizedidentity.didwebvh.core.crypto.MultikeyUtil;
import io.github.decentralizedidentity.didwebvh.core.url.DidToHttpsTransformer;
import io.github.decentralizedidentity.didwebvh.core.url.DidWebVhUrl;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.KeyWrapperUtil;

/** Resolves current did:webvh v1.0 assertion keys only after validating the complete history. */
public final class DidWebVhResolver implements DidResolver {
    static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final int MAX_CACHE_ENTRIES = 128;
    private final Function<String, String> fetch;
    private final long cacheTtlSeconds;
    private final Clock clock;
    private final Map<String, CachedDocument> cache = new LinkedHashMap<>(16, 0.75f, true);

    public DidWebVhResolver(KeycloakSession session, long cacheTtlSeconds) {
        this(url -> fetch(session, url), cacheTtlSeconds, Clock.systemUTC());
    }

    DidWebVhResolver(Function<String, String> fetch, long cacheTtlSeconds, Clock clock) {
        this.fetch = fetch;
        this.cacheTtlSeconds = Math.max(0, cacheTtlSeconds);
        this.clock = clock;
    }

    @Override
    public boolean supports(String did) {
        return did != null && did.startsWith("did:webvh:");
    }

    @Override
    public List<SignatureVerifierContext> resolve(String did, String keyId) {
        try {
            validateDid(did);
            JsonNode document;
            synchronized (cache) {
                CachedDocument cached = cache.get(did);
                document = cached != null && clock.instant().isBefore(cached.expiresAt()) ? cached.document() : null;
                if (document == null) {
                    cache.remove(did);
                }
            }
            if (document == null) {
                var validated = DidWebVhLog.validate(
                        did,
                        fetch.apply(DidToHttpsTransformer.toHttpsUrl(did)),
                        () -> fetch.apply(DidToHttpsTransformer.toWitnessUrl(did)));
                document = validated.document();
                long ttl = Math.min(cacheTtlSeconds, validated.ttl());
                if (ttl > 0) {
                    synchronized (cache) {
                        cache.put(
                                did,
                                new CachedDocument(document, clock.instant().plusSeconds(ttl)));
                        if (cache.size() > MAX_CACHE_ENTRIES) {
                            cache.remove(cache.keySet().iterator().next());
                        }
                    }
                }
            }
            return assertionKeys(document, did, keyId);
        } catch (DidResolutionException e) {
            throw e;
        } catch (Exception e) {
            throw new DidResolutionException("Unable to validate did:webvh issuer", e);
        }
    }

    static DidWebVhUrl validateDid(String did) {
        DidWebVhUrl parsed = DidWebVhUrl.parse(did);
        require(did.equals(parsed.toBaseDid()), "Issuer must be a base DID, without a version query or fragment");
        URI uri = URI.create(DidToHttpsTransformer.toHttpsUrl(did));
        require(
                "https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null,
                "DID must identify an HTTPS DNS host");
        for (String segment : parsed.getPathSegments()) {
            require(!segment.equals(".") && !segment.equals(".."), "DID path must not contain dot segments");
        }
        return parsed;
    }

    private static String fetch(KeycloakSession session, String url) {
        HttpGet request = new HttpGet(url);
        // Keep Keycloak's TLS/proxy configuration, but never follow a redirect to another scheme or host.
        request.setConfig(RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setConnectTimeout(10_000)
                .setSocketTimeout(10_000)
                .setConnectionRequestTimeout(10_000)
                .build());
        request.setHeader("Accept", "application/jsonl,application/json");
        try (var response =
                session.getProvider(HttpClientProvider.class).getHttpClient().execute(request)) {
            require(
                    response.getStatusLine().getStatusCode() == 200,
                    "DID artifact fetch failed (HTTP "
                            + response.getStatusLine().getStatusCode() + ")");
            require(response.getEntity() != null, "DID artifact response is empty");
            try (var input = response.getEntity().getContent()) {
                byte[] body = input.readNBytes(MAX_RESPONSE_BYTES + 1);
                require(body.length <= MAX_RESPONSE_BYTES, "DID artifact exceeds 1 MiB");
                return new String(body, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            throw new DidResolutionException("Unable to fetch did:webvh artifact", e);
        } finally {
            request.releaseConnection();
        }
    }

    private static List<SignatureVerifierContext> assertionKeys(JsonNode document, String did, String keyId) {
        Map<String, JsonNode> methods = new HashMap<>();
        for (JsonNode method : document.path("verificationMethod")) {
            addMethod(methods, method, did);
        }
        JsonNode assertions = document.path("assertionMethod");
        require(assertions.isArray() && !assertions.isEmpty(), "DID has no assertionMethod keys");
        List<SignatureVerifierContext> result = new ArrayList<>();
        String requested = keyId == null || keyId.isBlank() ? null : absoluteId(keyId, did);
        for (JsonNode assertion : assertions) {
            if (assertion.isObject()) {
                addMethod(methods, assertion, did);
            }
            String id = absoluteId(
                    assertion.isTextual()
                            ? assertion.textValue()
                            : assertion.path("id").asText(),
                    did);
            if (requested != null && !requested.equals(id)) {
                continue;
            }
            JsonNode method = methods.get(id);
            require(
                    method != null && did.equals(method.path("controller").asText()),
                    "Assertion key must be defined and controlled by the issuer DID");
            JsonNode jwk = method.get("publicKeyJwk");
            if (jwk == null) {
                byte[] raw =
                        MultikeyUtil.decode(method.path("publicKeyMultibase").asText());
                require(raw.length == 32, "Unsupported or invalid assertion multikey (expected Ed25519)");
                jwk = DidWebVhLog.JSON
                        .createObjectNode()
                        .put("kty", "OKP")
                        .put("crv", "Ed25519")
                        .put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
            }
            require(
                    jwk.isObject()
                            && Set.of("EC", "RSA", "OKP")
                                    .contains(jwk.path("kty").asText()),
                    "Assertion JWK must be an asymmetric public key");
            for (String privateField : List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k")) {
                require(!jwk.has(privateField), "Assertion JWK contains private key material");
            }
            require(!jwk.has("use") || "sig".equals(jwk.path("use").asText()), "Assertion JWK is not a signing key");
            if (jwk.has("key_ops")) {
                require(
                        jwk.get("key_ops").isArray()
                                && jwk.get("key_ops").size() == 1
                                && "verify".equals(jwk.get("key_ops").get(0).asText()),
                        "Assertion JWK must permit verification");
            }
            var wrapper = JWKSUtils.getKeyWrapper(
                    JWKParser.create().parse(jwk.toString()).getJwk());
            require(wrapper != null, "Unsupported assertion JWK");
            result.add(KeyWrapperUtil.createSignatureVerifierContext(wrapper));
        }
        require(!result.isEmpty(), "Requested kid is not an issuer assertionMethod");
        return List.copyOf(result);
    }

    private static void addMethod(Map<String, JsonNode> methods, JsonNode method, String did) {
        require(method.isObject() && method.path("id").isTextual(), "Invalid verification method");
        String id = absoluteId(method.get("id").textValue(), did);
        JsonNode previous = methods.putIfAbsent(id, method);
        require(previous == null || previous.equals(method), "Conflicting verification method IDs");
    }

    private static String absoluteId(String id, String did) {
        String absolute = id.startsWith("#") ? did + id : id;
        require(
                absolute.startsWith(did + "#") && absolute.length() > did.length() + 1,
                "Key reference must be a fragment of the issuer DID");
        return absolute;
    }

    static void require(boolean valid, String message) {
        if (!valid) {
            throw new DidResolutionException(message);
        }
    }

    private record CachedDocument(JsonNode document, Instant expiresAt) {}
}
