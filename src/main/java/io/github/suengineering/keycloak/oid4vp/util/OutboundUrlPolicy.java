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
package io.github.suengineering.keycloak.oid4vp.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.util.Locale;
import org.keycloak.models.KeycloakSession;

/**
 * Guards fetches whose URL comes from a presented credential (status lists, did:web documents,
 * issuer metadata and its jwks_uri). Anyone can present a self-made credential, so without this
 * Keycloak could be made to request internal addresses. URLs an administrator configured (trust
 * lists, VICAL) are not checked here.
 *
 * <p>Private, loopback, link-local and similar addresses are refused unless the identity provider
 * allows private networks. The check resolves the host before the request; it does not stop DNS
 * rebinding between the check and the connection.
 */
public final class OutboundUrlPolicy {

    /** KeycloakSession attribute set by the identity provider for the current request. */
    public static final String ALLOW_PRIVATE_NETWORKS_ATTRIBUTE = "oid4vp.allowPrivateNetworks";

    private OutboundUrlPolicy() {}

    public static void allowPrivateNetworks(KeycloakSession session, boolean allow) {
        if (session != null) session.setAttribute(ALLOW_PRIVATE_NETWORKS_ATTRIBUTE, allow);
    }

    /** Throws when {@code url} is not http(s) or, unless allowed, resolves to a non-public address. */
    public static void check(KeycloakSession session, String url) {
        boolean allowPrivate = session != null
                && Boolean.TRUE.equals(session.getAttribute(ALLOW_PRIVATE_NETWORKS_ATTRIBUTE, Boolean.class));
        check(url, allowPrivate);
    }

    static void check(String url, boolean allowPrivate) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Refusing to fetch a malformed URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !scheme.equals("http")) {
            throw new IllegalStateException("Refusing to fetch a non-HTTP URL");
        }
        if (uri.getHost() == null || uri.getRawUserInfo() != null) {
            throw new IllegalStateException("Refusing to fetch a URL without a plain host");
        }
        if (allowPrivate) return;
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(uri.getHost());
        } catch (Exception e) {
            throw new IllegalStateException("Refusing to fetch: host does not resolve");
        }
        for (InetAddress address : addresses) {
            if (!isPublic(address)) {
                throw new IllegalStateException("Refusing to fetch a private or local address");
            }
        }
    }

    static boolean isPublic(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        byte[] b = address.getAddress();
        if (address instanceof Inet6Address) {
            if ((b[0] & 0xfe) == 0xfc) return false; // fc00::/7 unique local
            boolean v4Mapped = true;
            for (int i = 0; i < 10; i++) v4Mapped &= b[i] == 0;
            v4Mapped &= (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff;
            if (v4Mapped) {
                try {
                    return isPublic(InetAddress.getByAddress(new byte[] {b[12], b[13], b[14], b[15]}));
                } catch (Exception e) {
                    return false;
                }
            }
            return true;
        }
        int first = b[0] & 0xff;
        int second = b[1] & 0xff;
        if (first == 0) return false; // 0.0.0.0/8
        if (first == 100 && second >= 64 && second <= 127) return false; // 100.64.0.0/10 carrier-grade NAT
        if (first == 198 && (second == 18 || second == 19)) return false; // 198.18.0.0/15 benchmarking
        if (first >= 240) return false; // reserved and broadcast
        return true;
    }
}
