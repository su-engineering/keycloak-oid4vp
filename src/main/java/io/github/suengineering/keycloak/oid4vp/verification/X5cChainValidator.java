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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

/**
 * Validates x5c certificate chains against a set of trusted CA certificates.
 * Shared by SD-JWT, mDoc, status list, and trust list signature verification.
 *
 * <p>Performs both signature chain validation and certificate validity period checks
 * ({@link X509Certificate#checkValidity()}) on all certificates in the presented chain.
 */
public final class X5cChainValidator {

    private static final Logger LOG = Logger.getLogger(X5cChainValidator.class);

    private X5cChainValidator() {}

    static JWSInput parseJwt(String compactJwt) {
        try {
            return new JWSInput(compactJwt);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse compact JWS/JWT", e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseClaims(JWSInput jwt) {
        try {
            return JsonSerialization.readValue(jwt.getContent(), Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT claims", e);
        }
    }

    static void verifyJwtSignature(JWSInput jwt, PublicKey publicKey) throws Exception {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPublicKey(publicKey);
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setAlgorithm(jwt.getHeader().getRawAlgorithm());
        keyWrapper.setType(resolveKeyType(publicKey));

        SignatureVerifierContext verifier = KeyWrapperUtil.createSignatureVerifierContext(keyWrapper);
        if (!verifier.verify(jwt.getEncodedSignatureInput().getBytes(StandardCharsets.US_ASCII), jwt.getSignature())) {
            throw new IllegalArgumentException("JWT signature verification failed");
        }
    }

    static PublicKey validateChain(List<String> x5c, List<X509Certificate> trustedCertificates) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain = new ArrayList<>();
        for (String certB64 : x5c) {
            byte[] certDer = Base64.getMimeDecoder().decode(certB64);
            chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer)));
        }
        return validateCertChain(chain, trustedCertificates);
    }

    static PublicKey validateCertChain(List<X509Certificate> chain, List<X509Certificate> trustedCertificates)
            throws Exception {
        if (chain.isEmpty()) {
            throw new IllegalStateException("Empty x5c chain");
        }

        X509Certificate leaf = chain.get(0);
        LOG.debugf("x5c leaf certificate: %s", leaf.getSubjectX500Principal().getName());

        for (int i = 0; i < chain.size(); i++) {
            try {
                chain.get(i).checkValidity();
            } catch (CertificateExpiredException e) {
                throw new IllegalStateException(
                        "x5c certificate at position " + i + " has expired: "
                                + chain.get(i).getSubjectX500Principal().getName(),
                        e);
            } catch (CertificateNotYetValidException e) {
                throw new IllegalStateException(
                        "x5c certificate at position " + i + " is not yet valid: "
                                + chain.get(i).getSubjectX500Principal().getName(),
                        e);
            }
        }

        if (chain.size() > 1 && leaf.getBasicConstraints() >= 0) {
            throw new IllegalStateException("x5c leaf certificate must not be a CA certificate");
        }

        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate certificate = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            if (issuer.getBasicConstraints() < 0) {
                throw new IllegalStateException(
                        "x5c issuer certificate at position " + (i + 1) + " is not a CA certificate");
            }
            certificate.verify(issuer.getPublicKey());
        }

        X509Certificate topOfChain = chain.get(chain.size() - 1);
        if (chain.size() > 1 && topOfChain.getBasicConstraints() < 0) {
            throw new IllegalStateException("x5c top certificate must be a CA certificate");
        }
        // A chain whose leaf is itself a trusted certificate (pinned end-entity) is accepted as is.
        for (X509Certificate trusted : currentlyValid(trustedCertificates)) {
            if (Arrays.equals(trusted.getEncoded(), leaf.getEncoded())) {
                LOG.debugf(
                        "x5c leaf is a pinned trusted certificate: %s",
                        trusted.getSubjectX500Principal().getName());
                return leaf.getPublicKey();
            }
        }
        for (X509Certificate trusted : currentlyValid(trustedCertificates)) {
            if (trusted.getBasicConstraints() < 0) {
                // Only CA certificates may anchor a presented chain.
                continue;
            }
            try {
                topOfChain.verify(trusted.getPublicKey());
                LOG.debugf(
                        "x5c chain anchored by trusted certificate: %s",
                        trusted.getSubjectX500Principal().getName());
                return leaf.getPublicKey();
            } catch (Exception ignored) {
            }
        }

        throw new IllegalStateException("x5c chain not anchored by any trusted certificate");
    }

    public static void validateConfiguredVerifierChain(List<X509Certificate> chain) throws Exception {
        if (chain.isEmpty()) {
            throw new IllegalStateException("Verifier x5c chain is empty");
        }

        for (int i = 0; i < chain.size(); i++) {
            X509Certificate certificate = chain.get(i);
            try {
                certificate.checkValidity();
            } catch (CertificateExpiredException e) {
                throw new IllegalStateException(
                        "Verifier certificate at position " + i + " has expired: "
                                + certificate.getSubjectX500Principal().getName(),
                        e);
            } catch (CertificateNotYetValidException e) {
                throw new IllegalStateException(
                        "Verifier certificate at position " + i + " is not yet valid: "
                                + certificate.getSubjectX500Principal().getName(),
                        e);
            }
        }

        X509Certificate leaf = chain.get(0);
        if (leaf.getBasicConstraints() >= 0) {
            throw new IllegalStateException("HAIP verifier leaf certificate must not be a CA certificate");
        }

        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate certificate = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            if (issuer.getBasicConstraints() < 0) {
                throw new IllegalStateException(
                        "Verifier certificate issuer at position " + (i + 1) + " is not a CA certificate");
            }
            certificate.verify(issuer.getPublicKey());
        }

        X509Certificate top = chain.get(chain.size() - 1);
        if (top.getBasicConstraints() < 0) {
            throw new IllegalStateException("Verifier x5c top certificate must be a CA certificate");
        }
        if (chain.size() == 1) {
            throw new IllegalStateException("HAIP requires x509_hash verifier certificates to be CA-issued");
        }
    }

    static void verifyJwtSignature(String compactJwt, List<X509Certificate> trustedCerts) throws Exception {
        JWSInput jwt = parseJwt(compactJwt);

        List<String> x5c = jwt.getHeader().getX5c();
        if (x5c == null) {
            x5c = List.of();
        }
        if (!x5c.isEmpty()) {
            // A presented chain is authoritative: if it does not validate, the JWT is rejected rather
            // than retried against the trusted keys, which would bypass the chain's own constraints.
            PublicKey leafKey;
            try {
                leafKey = validateChain(x5c, trustedCerts);
            } catch (Exception e) {
                throw new IllegalStateException("JWT x5c chain validation failed: " + e.getMessage(), e);
            }
            verifyJwtSignature(jwt, leafKey);
            LOG.debug("JWT signature verified via x5c chain");
            return;
        }

        for (X509Certificate cert : currentlyValid(trustedCerts)) {
            try {
                verifyJwtSignature(jwt, cert.getPublicKey());
                LOG.debug("JWT signature verified with trusted key");
                return;
            } catch (Exception e) {
            }
        }

        throw new IllegalStateException("JWT signature verification failed: no trusted key matched");
    }

    /** Returns the trusted certificates that are within their validity period. */
    static List<X509Certificate> currentlyValid(List<X509Certificate> certificates) {
        if (certificates == null) {
            return List.of();
        }
        List<X509Certificate> valid = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            try {
                certificate.checkValidity();
                valid.add(certificate);
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                LOG.debugf(
                        "Ignoring trusted certificate outside its validity period: %s",
                        certificate.getSubjectX500Principal().getName());
            }
        }
        return valid;
    }

    private static String resolveKeyType(PublicKey publicKey) {
        return switch (publicKey.getAlgorithm()) {
            case "EC", "ECDSA" -> KeyType.EC;
            case "RSA" -> KeyType.RSA;
            case "EdDSA", "Ed25519", "Ed448" -> KeyType.OKP;
            default ->
                throw new IllegalArgumentException("Unsupported signature key type: " + publicKey.getAlgorithm());
        };
    }
}
