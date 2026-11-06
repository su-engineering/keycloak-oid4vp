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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * A wallet-relying party registration certificate (ETSI TS 119 475, JWT type {@code rc-wrp+jwt}).
 *
 * <p>The verifier passes it to wallets in {@code verifier_info} as
 * {@code {"format": "registration_cert", "data": base64url(JWT)}}. Wallets check its signature and
 * registrar, that it belongs to the access certificate that signs the request, and that the request
 * asks only for registered credentials and claims (ARF RPRC_21). This class runs the same checks on
 * the verifier's own configuration so a mismatch shows up in the Keycloak log instead of as a
 * refused presentation.
 */
public final class RegistrationCertificate {

    public static final String TYP = "rc-wrp+jwt";
    public static final String VERIFIER_INFO_FORMAT = "registration_cert";
    private static final String ORGANIZATION_IDENTIFIER_OID = "2.5.4.97";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final String jwt;
    private final JsonNode header;
    private final JsonNode claims;
    private final List<X509Certificate> chain;

    private RegistrationCertificate(String jwt, JsonNode header, JsonNode claims, List<X509Certificate> chain) {
        this.jwt = jwt;
        this.header = header;
        this.claims = claims;
        this.chain = chain;
    }

    /** Parses a compact JWT, or the base64url encoding of one. */
    public static RegistrationCertificate parse(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Empty registration certificate");
        String jwt = value.trim();
        if (jwt.chars().filter(c -> c == '.').count() != 2) {
            jwt = new String(Base64.getUrlDecoder().decode(jwt.replace("=", "")), StandardCharsets.UTF_8).trim();
        }
        try {
            String[] parts = jwt.split("\\.");
            JsonNode header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
            JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
            List<X509Certificate> chain = new ArrayList<>();
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (JsonNode cert : header.path("x5c")) {
                chain.add((X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(Base64.getMimeDecoder().decode(cert.asText()))));
            }
            return new RegistrationCertificate(jwt, header, claims, List.copyOf(chain));
        } catch (Exception e) {
            throw new IllegalArgumentException("Unreadable registration certificate: " + e.getMessage(), e);
        }
    }

    private boolean signatureVerifies(X509Certificate signer) {
        String algorithm =
                switch (header.path("alg").asText()) {
                    case "ES256" -> "SHA256withECDSAinP1363Format";
                    case "ES384" -> "SHA384withECDSAinP1363Format";
                    case "ES512" -> "SHA512withECDSAinP1363Format";
                    case "RS256" -> "SHA256withRSA";
                    default -> null;
                };
        if (algorithm == null) return false;
        try {
            int lastDot = jwt.lastIndexOf('.');
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(signer.getPublicKey());
            verifier.update(jwt.substring(0, lastDot).getBytes(StandardCharsets.US_ASCII));
            return verifier.verify(Base64.getUrlDecoder().decode(jwt.substring(lastDot + 1)));
        } catch (Exception e) {
            return false;
        }
    }

    /** The {@code verifier_info} entry carrying this certificate. */
    public Map<String, Object> verifierInfoEntry() {
        return Map.of(
                "format",
                VERIFIER_INFO_FORMAT,
                "data",
                Base64.getUrlEncoder().withoutPadding().encodeToString(jwt.getBytes(StandardCharsets.US_ASCII)));
    }

    /**
     * Problems a wallet would report about this certificate together with {@code accessCertificate},
     * the certificate that signs the request. Each completes "the registration certificate ...".
     */
    public List<String> problems(X509Certificate accessCertificate, Instant now) {
        List<String> problems = new ArrayList<>();
        if (!TYP.equalsIgnoreCase(header.path("typ").asText())
                && !("application/" + TYP).equalsIgnoreCase(header.path("typ").asText())) {
            problems.add("has typ \"" + header.path("typ").asText() + "\" instead of " + TYP);
        }
        if (chain.isEmpty()) {
            problems.add("has no x5c certificate");
        } else {
            if (!signatureVerifies(chain.get(0))) {
                problems.add("has a signature that does not verify with its x5c leaf");
            }
        }
        if (claims.has("exp")
                && !now.isBefore(Instant.ofEpochSecond(claims.path("exp").asLong()))) {
            problems.add(
                    "expired at " + Instant.ofEpochSecond(claims.path("exp").asLong()));
        }
        if (accessCertificate == null) {
            problems.add("is configured without an access certificate (x509CertificatePem) to sign requests with");
            return problems;
        }
        boolean intermediated = claims.path("act").path("sub").isTextual();
        String identifier = intermediated
                ? claims.path("act").path("sub").asText()
                : claims.path("sub").asText();
        String accessIdentifier = subjectAttribute(accessCertificate, ORGANIZATION_IDENTIFIER_OID);
        if (identifier.isBlank() || !identifier.equals(accessIdentifier)) {
            problems.add("identifies \"" + identifier + "\", but the access certificate's organizationIdentifier is \""
                    + accessIdentifier + "\"");
        }
        if (!intermediated) {
            String service = claims.path("serviceIdentifier").asText("");
            String accessService = subjectAttribute(accessCertificate, "OU");
            if (!service.equals(accessService == null ? "" : accessService)) {
                problems.add("is for the service \"" + service
                        + "\", but the access certificate's organizationalUnit is \"" + accessService + "\"");
            }
        }
        return problems;
    }

    /**
     * What the DCQL query asks for beyond the registered credentials (ARF RPRC_21). Empty when the
     * certificate registers no credentials, or when everything requested is registered.
     */
    public List<String> overAsking(String dcqlQuery) {
        List<String> findings = new ArrayList<>();
        JsonNode registered = claims.path("credentials");
        if (!registered.isArray() || registered.isEmpty()) return findings;
        JsonNode query;
        try {
            query = JSON.readTree(dcqlQuery);
        } catch (Exception e) {
            return findings;
        }
        for (JsonNode credential : query.path("credentials")) {
            String format = credential.path("format").asText();
            List<String> types = types(credential.path("meta"));
            List<String> missingTypes = new ArrayList<>();
            for (String type : types) {
                if (registeredFor(registered, format, type).isEmpty()) missingTypes.add(type);
            }
            if (types.isEmpty()) {
                findings.add(format + " without a credential type");
                continue;
            }
            if (!missingTypes.isEmpty()) {
                findings.add(String.join(", ", missingTypes));
                continue;
            }
            for (JsonNode claim : credential.path("claims")) {
                JsonNode path = claim.path("path");
                if (!path.isArray() || path.isEmpty()) continue;
                for (String type : types) {
                    boolean covered = registeredFor(registered, format, type).stream()
                            .anyMatch(entry -> registeredPaths(entry).stream().anyMatch(p -> isPrefix(p, path)));
                    if (!covered) {
                        findings.add(describe(path) + " of " + type);
                        break;
                    }
                }
            }
        }
        return findings;
    }

    private static List<JsonNode> registeredFor(JsonNode registered, String format, String type) {
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode entry : registered) {
            if (format.equals(entry.path("format").asText())
                    && types(entry.path("meta")).contains(type)) out.add(entry);
        }
        return out;
    }

    private static List<JsonNode> registeredPaths(JsonNode entry) {
        List<JsonNode> paths = new ArrayList<>();
        // ETSI TS 119 475 names the member "claim"; accept "claims" as DCQL spells it.
        for (String member : List.of("claim", "claims")) {
            for (JsonNode claim : entry.path(member)) {
                if (claim.path("path").isArray()) paths.add(claim.path("path"));
            }
        }
        return paths;
    }

    private static List<String> types(JsonNode meta) {
        List<String> types = new ArrayList<>();
        for (JsonNode vct : meta.path("vct_values")) types.add(vct.asText());
        if (meta.path("doctype_value").isTextual())
            types.add(meta.path("doctype_value").asText());
        return types;
    }

    /** A registered parent path such as {@code address} also covers {@code address.street_address}. */
    private static boolean isPrefix(JsonNode registered, JsonNode requested) {
        if (registered.size() > requested.size()) return false;
        for (int i = 0; i < registered.size(); i++) {
            if (!registered.get(i).asText().equals(requested.get(i).asText())) return false;
        }
        return true;
    }

    private static String describe(JsonNode path) {
        List<String> parts = new ArrayList<>();
        path.forEach(part -> parts.add(part.isNull() ? "*" : part.asText()));
        return String.join(".", parts);
    }

    /** Reads a subject attribute by short name or OID; values the JDK cannot name arrive hex-encoded. */
    static String subjectAttribute(X509Certificate certificate, String type) {
        try {
            String name = certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
            for (Rdn rdn : new LdapName(name).getRdns()) {
                if (!type.equalsIgnoreCase(rdn.getType())
                        && !("OID." + type).equalsIgnoreCase(rdn.getType())
                        && !(ORGANIZATION_IDENTIFIER_OID.equals(type)
                                && "organizationIdentifier".equalsIgnoreCase(rdn.getType()))) {
                    continue;
                }
                Object value = rdn.getValue();
                if (value instanceof byte[] der) return derString(der);
                String text = value.toString();
                if (text.startsWith("#"))
                    return derString(java.util.HexFormat.of().parseHex(text.substring(1)));
                return text;
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private static String derString(byte[] der) {
        int length = der[1] & 0xff;
        int offset = 2;
        if (length > 0x80) {
            int bytes = length & 0x7f;
            length = 0;
            for (int i = 0; i < bytes; i++) length = (length << 8) | (der[2 + i] & 0xff);
            offset = 2 + bytes;
        }
        return new String(der, offset, length, StandardCharsets.UTF_8);
    }

    public JsonNode claims() {
        return claims;
    }
}
