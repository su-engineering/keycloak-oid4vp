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
package io.github.suengineering.keycloak.oid4vp.verification;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Whether an X.509 certificate names an SD-JWT VC issuer (SD-JWT VC, x5c issuer key resolution):
 * the {@code iss} value must appear as a uniformResourceIdentifier subject alternative name, or its
 * host as a dNSName. Without this, any certificate anchored in the trust list could sign credentials
 * claiming any issuer, and an issuer allowlist would compare an unbound string.
 */
final class IssuerCertificateBinding {

    private static final int SAN_DNS = 2;
    private static final int SAN_URI = 6;

    private IssuerCertificateBinding() {}

    static boolean names(X509Certificate certificate, String issuer) {
        if (certificate == null || issuer == null || issuer.isBlank()) return false;
        URI issuerUri;
        try {
            issuerUri = URI.create(issuer.trim());
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (!"https".equalsIgnoreCase(issuerUri.getScheme()) || issuerUri.getHost() == null) {
            return false;
        }
        Collection<List<?>> names;
        try {
            names = certificate.getSubjectAlternativeNames();
        } catch (Exception e) {
            return false;
        }
        if (names == null) return false;
        String host = issuerUri.getHost().toLowerCase(Locale.ROOT);
        for (List<?> name : names) {
            if (name.size() < 2 || !(name.get(0) instanceof Integer type) || !(name.get(1) instanceof String value)) {
                continue;
            }
            if (type == SAN_URI && sameUri(value, issuer)) return true;
            if (type == SAN_DNS && host.equals(value.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private static boolean sameUri(String san, String issuer) {
        return stripSlash(san).equalsIgnoreCase(stripSlash(issuer.trim()));
    }

    private static String stripSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
