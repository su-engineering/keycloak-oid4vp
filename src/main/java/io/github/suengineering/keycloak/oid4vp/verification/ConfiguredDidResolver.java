/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

/** Routes issuer DIDs only to methods explicitly enabled for this identity provider. */
public final class ConfiguredDidResolver implements DidResolver {
    private final Set<String> allowed;
    private final List<DidResolver> resolvers;

    public ConfiguredDidResolver(KeycloakSession session, String methods, long cacheTtlSeconds) {
        this(
                methods,
                List.of(new DidWebResolver(session, cacheTtlSeconds), new DidWebVhResolver(session, cacheTtlSeconds)));
    }

    ConfiguredDidResolver(String methods, List<DidResolver> resolvers) {
        this.allowed = Arrays.stream(methods.split(",")).map(String::trim).collect(Collectors.toUnmodifiableSet());
        this.resolvers = List.copyOf(resolvers);
    }

    @Override
    public boolean supports(String did) {
        return allowed.contains(method(did)) && resolvers.stream().anyMatch(r -> r.supports(did));
    }

    @Override
    public List<SignatureVerifierContext> resolve(String did, String keyId) {
        if (!allowed.contains(method(did))) {
            throw new DidResolutionException("DID method is not enabled for this identity provider");
        }
        return resolvers.stream()
                .filter(r -> r.supports(did))
                .findFirst()
                .orElseThrow(() -> new DidResolutionException("Unsupported DID method"))
                .resolve(did, keyId);
    }

    private static String method(String did) {
        int end = did == null ? -1 : did.indexOf(':', 4);
        return end < 0 ? "" : did.substring(0, end);
    }
}
