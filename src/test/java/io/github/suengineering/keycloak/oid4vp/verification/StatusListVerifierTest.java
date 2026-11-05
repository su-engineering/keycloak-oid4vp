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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.zip.Deflater;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class StatusListVerifierTest {

    private final StatusListVerifier verifier = new StatusListVerifier();

    @AfterEach
    void clearCaches() {
        StatusListVerifier.clearCache();
    }

    @Test
    void constructorWithMaxCacheTtl_acceptsZero() {
        StatusListVerifier v = new StatusListVerifier(null, null, Duration.ZERO);
        // Should not throw; verifier is functional for non-HTTP operations
        v.checkRevocationStatus(Map.of("given_name", "Alice"));
    }

    @Test
    void constructorWithMaxCacheTtl_acceptsNull() {
        StatusListVerifier v = new StatusListVerifier(null, null, null);
        v.checkRevocationStatus(Map.of());
    }

    @Test
    void extractsStatusReferenceFromValidPayload() {
        Map<String, Object> payload =
                Map.of("status", Map.of("status_list", Map.of("uri", "https://issuer.example/status/abc", "idx", 42)));

        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);
        assertThat(ref).isNotNull();
        assertThat(ref.uri()).isEqualTo("https://issuer.example/status/abc");
        assertThat(ref.idx()).isEqualTo(42);
    }

    @Test
    void returnsNullForMissingStatusClaim() {
        assertThat(verifier.extractStatusReference(Map.of())).isNull();
        assertThat(verifier.extractStatusReference(Map.of("status", "not-a-map")))
                .isNull();
        assertThat(verifier.extractStatusReference(null)).isNull();
    }

    @Test
    void returnsNullForMalformedStatusList() {
        Map<String, Object> payload = Map.of("status", Map.of("status_list", Map.of("uri", "https://example.com")));
        assertThat(verifier.extractStatusReference(payload)).isNull();
    }

    @Test
    void returnsNullForNonNumericStatusIndex() {
        Map<String, Object> payload =
                Map.of("status", Map.of("status_list", Map.of("uri", "https://example.com", "idx", "abc")));
        assertThat(verifier.extractStatusReference(payload)).isNull();
    }

    @Test
    void extractsStatusReferenceFromStringIndex() {
        Map<String, Object> payload =
                Map.of("status", Map.of("status_list", Map.of("uri", "https://example.com", "idx", "17")));
        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);
        assertThat(ref).isNotNull();
        assertThat(ref.idx()).isEqualTo(17);
    }

    @Test
    void extractsStatusReferenceFromJsonNodeValues() {
        Map<String, Object> payload = Map.of(
                "status",
                Map.of(
                        "status_list",
                        Map.of(
                                "uri", TextNode.valueOf("https://issuer.example/status/abc"),
                                "idx", IntNode.valueOf(42))));

        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);

        assertThat(ref).isNotNull();
        assertThat(ref.uri()).isEqualTo("https://issuer.example/status/abc");
        assertThat(ref.idx()).isEqualTo(42);
    }

    @Test
    void returnsNullWhenStatusListIsMissing() {
        Map<String, Object> payload = Map.of("status", Map.of("other_field", "value"));
        assertThat(verifier.extractStatusReference(payload)).isNull();
    }

    @Test
    void getStatusAtIndexReturnsZeroForValidEntry() {
        byte[] bits = new byte[] {0x00, 0x00};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 1)).isEqualTo(0);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 7, 1)).isEqualTo(0);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 15, 1)).isEqualTo(0);
    }

    @Test
    void getStatusAtIndexDetectsRevokedBit() {
        byte[] bits = new byte[] {0x02};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 1)).isEqualTo(0);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 1)).isEqualTo(1);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 2, 1)).isEqualTo(0);
    }

    @Test
    void getStatusAtIndexSupportsMultiBit() {
        byte[] bits = new byte[] {(byte) 0x0B};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 2)).isEqualTo(3);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 2)).isEqualTo(2);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 2, 2)).isEqualTo(0);
    }

    @Test
    void getStatusAtIndexThrowsForOutOfRange() {
        byte[] bits = new byte[] {0x00};
        assertThatThrownBy(() -> StatusListVerifier.getStatusAtIndex(bits, 100, 1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("out of range");
    }

    @Test
    void getStatusAtIndexRejectsBitsValueOutsideSpec() {
        byte[] bits = new byte[] {0x00};
        assertThatThrownBy(() -> StatusListVerifier.getStatusAtIndex(bits, 0, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("one of 1, 2, 4, or 8");
    }

    @Test
    void getStatusAtIndexSupportsEightBitStatuses() {
        byte[] bits = new byte[] {(byte) 0xFE, (byte) 0x7F};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 8)).isEqualTo(254);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 8)).isEqualTo(127);
    }

    @Test
    void getStatusAtIndexSupportsFourBitStatuses() {
        byte[] bits = new byte[] {(byte) 0xAB};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 4)).isEqualTo(11);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 4)).isEqualTo(10);
    }

    @Test
    void getStatusAtIndexRejectsEmptyStatusList() {
        assertThatThrownBy(() -> StatusListVerifier.getStatusAtIndex(new byte[0], 0, 1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Empty status list");
    }

    @Test
    void inflateRoundTripRawDeflate() throws Exception {
        byte[] original = new byte[] {0x00, 0x01, 0x02, (byte) 0xFF, 0x00, 0x55};

        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(original);
        deflater.finish();
        byte[] compressed = new byte[256];
        int compressedLen = deflater.deflate(compressed);
        deflater.end();

        byte[] trimmed = new byte[compressedLen];
        System.arraycopy(compressed, 0, trimmed, 0, compressedLen);

        byte[] inflated = StatusListVerifier.inflate(trimmed);
        assertThat(inflated).isEqualTo(original);
    }

    @Test
    void inflateRoundTripZlib() throws Exception {
        byte[] original = new byte[] {0x00, 0x01, 0x02, (byte) 0xFF, 0x00, 0x55};

        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, false);
        deflater.setInput(original);
        deflater.finish();
        byte[] compressed = new byte[256];
        int compressedLen = deflater.deflate(compressed);
        deflater.end();

        byte[] trimmed = new byte[compressedLen];
        System.arraycopy(compressed, 0, trimmed, 0, compressedLen);

        byte[] inflated = StatusListVerifier.inflate(trimmed);
        assertThat(inflated).isEqualTo(original);
    }

    @Test
    void checkRevocationStatusPassesWhenNoStatusClaim() {
        verifier.checkRevocationStatus(Map.of("given_name", "Alice"));
        verifier.checkRevocationStatus(Map.of());
    }

    @Test
    void checkRevocationStatusThrowsWhenCredentialIsRevoked() {
        StatusListVerifier revokedVerifier = new StatusListVerifier() {
            @Override
            DecodedStatusList fetchAndDecodeStatusList(String uri, StatusListTrust trust) {
                return new DecodedStatusList(new byte[] {0x01}, 1);
            }
        };

        assertThatThrownBy(() -> revokedVerifier.checkRevocationStatus(Map.of(
                        "status", Map.of("status_list", Map.of("uri", "https://issuer.example/status", "idx", 0)))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    void checkRevocationStatusWrapsUnexpectedVerifierFailures() {
        StatusListVerifier failingVerifier = new StatusListVerifier() {
            @Override
            DecodedStatusList fetchAndDecodeStatusList(String uri, StatusListTrust trust) throws Exception {
                throw new RuntimeException("simulated status list fetch failure");
            }
        };

        assertThatThrownBy(() -> failingVerifier.checkRevocationStatus(Map.of(
                        "status", Map.of("status_list", Map.of("uri", "https://issuer.example/status", "idx", 0)))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unable to verify credential revocation status");
    }

    @Test
    void extractsStatusReferenceWithLongIdx() {
        Map<String, Object> payload = Map.of(
                "status", Map.of("status_list", Map.of("uri", "https://issuer.example/status/mdoc", "idx", 53L)));
        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);
        assertThat(ref).isNotNull();
        assertThat(ref.idx()).isEqualTo(53);
    }

    @Test
    void extractsStatusReferenceFromMdocNamespacedKey() {
        Map<String, Object> claims = Map.of(
                "eu.europa.ec.eudi.pid.1/family_name",
                "Smith",
                "eu.europa.ec.eudi.pid.1/status",
                Map.of("status_list", Map.of("uri", "https://issuer.example/status", "idx", 7)));
        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(claims);
        assertThat(ref).isNotNull();
        assertThat(ref.uri()).isEqualTo("https://issuer.example/status");
        assertThat(ref.idx()).isEqualTo(7);
    }

    // --- validateStatusListToken tests ---

    @Test
    void validateStatusListTokenAcceptsValidToken() {
        verifier.validateStatusListToken(
                "statuslist+jwt",
                "https://issuer.example/status/1",
                Instant.now().plusSeconds(3600),
                "https://issuer.example/status/1");
    }

    @Test
    void validateStatusListTokenAcceptsNoExpiration() {
        verifier.validateStatusListToken(
                "statuslist+jwt", "https://issuer.example/status/1", null, "https://issuer.example/status/1");
    }

    @Test
    void validateStatusListTokenRejectsWrongTyp() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        "jwt", "https://issuer.example/status/1", null, "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("statuslist+jwt");
    }

    @Test
    void validateStatusListTokenRejectsMissingTyp() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        null, "https://issuer.example/status/1", null, "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("statuslist+jwt");
    }

    @Test
    void validateStatusListTokenRejectsSubMismatch() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        "statuslist+jwt", "https://other.example/status/2", null, "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void validateStatusListTokenRejectsExpiredToken() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        "statuslist+jwt",
                        "https://issuer.example/status/1",
                        Instant.now().minusSeconds(60),
                        "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired");
    }

    // --- resolveExpiry tests ---

    @Test
    void resolveExpiryUsesTtlClaim() {
        Instant expiry = verifier.resolveExpiry(null, 300);
        assertThat(expiry).isAfter(Instant.now().plusSeconds(290));
        assertThat(expiry).isBefore(Instant.now().plusSeconds(310));
    }

    @Test
    void resolveExpiryPrefersEarlierOfTtlAndExp() {
        Instant expiry = verifier.resolveExpiry(Instant.now().plusSeconds(3600), 300);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(310));
    }

    @Test
    void resolveExpiryPrefersExpWhenEarlierThanTtl() {
        Instant expTime = Instant.now().plusSeconds(120);
        Instant expiry = verifier.resolveExpiry(expTime, 3600);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(130));
        assertThat(expiry).isAfter(Instant.now().plusSeconds(110));
    }

    @Test
    void resolveExpiryFallsBackToExpWhenNoTtl() {
        Instant expTime = Instant.now().plusSeconds(600);
        Instant expiry = verifier.resolveExpiry(expTime, null);
        assertThat(expiry).isAfter(Instant.now().plusSeconds(595));
        assertThat(expiry).isBefore(Instant.now().plusSeconds(605));
    }

    @Test
    void resolveExpiryReturnsNowWhenNeitherTtlNorExp() {
        Instant before = Instant.now();
        Instant expiry = verifier.resolveExpiry(null, null);
        assertThat(expiry).isAfterOrEqualTo(before);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(2));
    }

    @Test
    void resolveExpiryCapsAtMaxCacheTtl() {
        StatusListVerifier capped = new StatusListVerifier(null, null, Duration.ofSeconds(60));
        Instant expiry = capped.resolveExpiry(null, 3600);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(65));
        assertThat(expiry).isAfter(Instant.now().plusSeconds(55));
    }

    @Test
    void resolveExpiryIgnoresNonPositiveTtl() {
        Instant expiry = verifier.resolveExpiry(Instant.now().plusSeconds(600), 0);
        assertThat(expiry).isAfter(Instant.now().plusSeconds(595));
    }

    @Test
    void resolveExpiryFallsBackToNowForNegativeTtlWithoutExp() {
        Instant before = Instant.now();
        Instant expiry = verifier.resolveExpiry(null, -60);
        assertThat(expiry).isAfterOrEqualTo(before);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(2));
    }

    @Test
    void inflateRejectsDecompressionBomb() {
        byte[] zeros = new byte[StatusListVerifier.MAX_DECOMPRESSED_STATUS_LIST_BYTES + 1024];
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(zeros);
        deflater.finish();
        byte[] buffer = new byte[1 << 20];
        int length = deflater.deflate(buffer);
        deflater.end();
        byte[] bomb = java.util.Arrays.copyOf(buffer, length);

        assertThatThrownBy(() -> StatusListVerifier.inflate(bomb))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("decompressed");
    }

    @Test
    void statusListTokenWithoutAnyTrustIsRejected() throws Exception {
        com.nimbusds.jose.jwk.ECKey key =
                new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate();
        String jwt = signedStatusListToken(key);

        assertThatThrownBy(() -> verifier.verifyStatusListJwtSignature(
                        jwt, StatusListVerifier.StatusListTrust.trustAnchorsOnly()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be verified");
    }

    @Test
    void statusListTokenSignedByCredentialIssuerKeyIsAccepted() throws Exception {
        org.keycloak.common.crypto.CryptoIntegration.init(getClass().getClassLoader());
        com.nimbusds.jose.jwk.ECKey issuerKey =
                new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate();
        com.nimbusds.jose.jwk.ECKey otherKey =
                new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate();

        StatusListVerifier.StatusListTrust trust = new StatusListVerifier.StatusListTrust(
                "did:web:issuer.example", java.util.List.of(verifierFor(issuerKey)));

        assertThat(verifier.verifyStatusListJwtSignature(signedStatusListToken(issuerKey), trust))
                .isEqualTo("issuer:did:web:issuer.example");
        assertThatThrownBy(() -> verifier.verifyStatusListJwtSignature(signedStatusListToken(otherKey), trust))
                .isInstanceOf(IllegalStateException.class);
    }

    private static String signedStatusListToken(com.nimbusds.jose.jwk.ECKey key) throws Exception {
        com.nimbusds.jose.JWSObject jws = new com.nimbusds.jose.JWSObject(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .type(new com.nimbusds.jose.JOSEObjectType("statuslist+jwt"))
                        .build(),
                new com.nimbusds.jose.Payload("{\"sub\":\"https://issuer.example/status\"}"));
        jws.sign(new com.nimbusds.jose.crypto.ECDSASigner(key));
        return jws.serialize();
    }

    private static org.keycloak.crypto.SignatureVerifierContext verifierFor(com.nimbusds.jose.jwk.ECKey key)
            throws Exception {
        org.keycloak.crypto.KeyWrapper wrapper = new org.keycloak.crypto.KeyWrapper();
        wrapper.setPublicKey(key.toECPublicKey());
        wrapper.setType(org.keycloak.crypto.KeyType.EC);
        wrapper.setUse(org.keycloak.crypto.KeyUse.SIG);
        wrapper.setAlgorithm("ES256");
        wrapper.setCurve("P-256");
        return org.keycloak.util.KeyWrapperUtil.createSignatureVerifierContext(wrapper);
    }

    @org.junit.jupiter.api.Nested
    class CwtStatusList {

        private static final String URI = "https://issuer.example/status/1";
        private java.security.KeyPair caKeys;
        private java.security.cert.X509Certificate caCert;
        private java.security.KeyPair signerKeys;
        private java.security.cert.X509Certificate signerCert;

        @org.junit.jupiter.api.BeforeEach
        void setUpPki() throws Exception {
            org.keycloak.common.crypto.CryptoIntegration.init(getClass().getClassLoader());
            caKeys = ecKeyPair();
            caCert = certificate(caKeys, caKeys, "CN=Status CA", "CN=Status CA", true);
            signerKeys = ecKeyPair();
            signerCert = certificate(signerKeys, caKeys, "CN=Status Signer", "CN=Status CA", false);
        }

        private StatusListVerifier verifierTrusting(java.security.cert.X509Certificate... anchors) {
            return new StatusListVerifier(null, new TrustListProvider(java.util.List.of(anchors)));
        }

        @Test
        void acceptsCwtWithAnchoredX5chainAndReadsStatuses() throws Exception {
            // statuses: index 0 = 0, index 1 = 1 (revoked), with 1 bit per status
            byte[] cwt = statusListCwt(
                    StatusListVerifier.STATUS_LIST_CWT_TYPE, URI, deflate(new byte[] {0b0000_0010}), signerKeys, true);

            StatusListVerifier.ParsedStatusList parsed = verifierTrusting(caCert)
                    .decodeCwtStatusList(cwt, URI, StatusListVerifier.StatusListTrust.trustAnchorsOnly());

            byte[] bits = StatusListVerifier.inflate(parsed.compressed());
            assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, parsed.bitsPerStatus()))
                    .isZero();
            assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, parsed.bitsPerStatus()))
                    .isEqualTo(1);
            assertThat(parsed.trustDomain()).isEqualTo("trust-anchors");
        }

        @Test
        void acceptsCwtSignedDirectlyByPinnedAnchorWithoutX5chain() throws Exception {
            byte[] cwt = statusListCwt(
                    StatusListVerifier.STATUS_LIST_CWT_TYPE, URI, deflate(new byte[] {0}), signerKeys, false);

            assertThat(verifierTrusting(signerCert)
                            .decodeCwtStatusList(cwt, URI, StatusListVerifier.StatusListTrust.trustAnchorsOnly())
                            .bitsPerStatus())
                    .isEqualTo(1);
        }

        @Test
        void rejectsCwtFromUntrustedSigner() throws Exception {
            java.security.KeyPair otherKeys = ecKeyPair();
            byte[] cwt = statusListCwt(
                    StatusListVerifier.STATUS_LIST_CWT_TYPE, URI, deflate(new byte[] {0}), otherKeys, false);

            assertThatThrownBy(() -> verifierTrusting(caCert)
                            .decodeCwtStatusList(cwt, URI, StatusListVerifier.StatusListTrust.trustAnchorsOnly()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not trusted");
        }

        @Test
        void rejectsCwtWithWrongTypeOrSubject() throws Exception {
            byte[] wrongType = statusListCwt("application/cwt", URI, deflate(new byte[] {0}), signerKeys, true);
            byte[] wrongSub = statusListCwt(
                    StatusListVerifier.STATUS_LIST_CWT_TYPE,
                    "https://other.example/status",
                    deflate(new byte[] {0}),
                    signerKeys,
                    true);
            StatusListVerifier verifier = verifierTrusting(caCert);

            assertThatThrownBy(() -> verifier.decodeCwtStatusList(
                            wrongType, URI, StatusListVerifier.StatusListTrust.trustAnchorsOnly()))
                    .hasMessageContaining("typ");
            assertThatThrownBy(() -> verifier.decodeCwtStatusList(
                            wrongSub, URI, StatusListVerifier.StatusListTrust.trustAnchorsOnly()))
                    .hasMessageContaining("sub claim");
        }

        @Test
        void acceptsCwtSignedByCredentialIssuerKey() throws Exception {
            byte[] cwt = statusListCwt(
                    StatusListVerifier.STATUS_LIST_CWT_TYPE, URI, deflate(new byte[] {0}), signerKeys, false);
            org.keycloak.crypto.KeyWrapper wrapper = new org.keycloak.crypto.KeyWrapper();
            wrapper.setPublicKey(signerKeys.getPublic());
            wrapper.setType(org.keycloak.crypto.KeyType.EC);
            wrapper.setUse(org.keycloak.crypto.KeyUse.SIG);
            wrapper.setAlgorithm("ES256");
            wrapper.setCurve("P-256");
            StatusListVerifier.StatusListTrust trust = new StatusListVerifier.StatusListTrust(
                    "did:web:issuer.example",
                    java.util.List.of(org.keycloak.util.KeyWrapperUtil.createSignatureVerifierContext(wrapper)));

            assertThat(new StatusListVerifier()
                            .decodeCwtStatusList(cwt, URI, trust)
                            .trustDomain())
                    .isEqualTo("issuer:did:web:issuer.example");
        }

        @Test
        void detectsCwtByMediaTypeOrBinaryBody() {
            assertThat(new StatusListVerifier.FetchedStatusList(new byte[] {(byte) 0xd2}, null).isCwt())
                    .isTrue();
            assertThat(new StatusListVerifier.FetchedStatusList("eyJhbGc".getBytes(), null).isCwt())
                    .isFalse();
            assertThat(new StatusListVerifier.FetchedStatusList("eyJhbGc".getBytes(), "application/statuslist+cwt")
                            .isCwt())
                    .isTrue();
        }

        private byte[] statusListCwt(
                String typ, String sub, byte[] compressed, java.security.KeyPair signer, boolean withX5chain)
                throws Exception {
            com.authlete.cbor.CBORPairList statusList = new com.authlete.cbor.CBORPairList(java.util.List.of(
                    new com.authlete.cbor.CBORPair(
                            new com.authlete.cbor.CBORString("bits"), new com.authlete.cbor.CBORInteger(1)),
                    new com.authlete.cbor.CBORPair(
                            new com.authlete.cbor.CBORString("lst"), new com.authlete.cbor.CBORByteArray(compressed))));
            com.authlete.cbor.CBORPairList claims = new com.authlete.cbor.CBORPairList(java.util.List.of(
                    new com.authlete.cbor.CBORPair(
                            new com.authlete.cbor.CBORInteger(2), new com.authlete.cbor.CBORString(sub)),
                    new com.authlete.cbor.CBORPair(
                            new com.authlete.cbor.CBORInteger(6),
                            new com.authlete.cbor.CBORLong(Instant.now().getEpochSecond())),
                    new com.authlete.cbor.CBORPair(
                            new com.authlete.cbor.CBORInteger(4),
                            new com.authlete.cbor.CBORLong(
                                    Instant.now().plusSeconds(3600).getEpochSecond())),
                    new com.authlete.cbor.CBORPair(new com.authlete.cbor.CBORInteger(65533), statusList)));
            byte[] payload = claims.encode();

            com.authlete.cose.COSEProtectedHeaderBuilder protectedBuilder =
                    new com.authlete.cose.COSEProtectedHeaderBuilder().alg(-7).put(16, typ);
            if (withX5chain) {
                protectedBuilder.x5chain(java.util.List.of(signerCert, caCert));
            }
            com.authlete.cose.COSEProtectedHeader protectedHeader = protectedBuilder.build();
            var toBeSigned = new com.authlete.cose.SigStructureBuilder()
                    .signature1()
                    .bodyAttributes(protectedHeader)
                    .payload(payload)
                    .build();
            byte[] signature = new com.authlete.cose.COSESigner(signer.getPrivate()).sign(toBeSigned, -7);
            com.authlete.cose.COSESign1 sign1 = new com.authlete.cose.COSESign1Builder()
                    .protectedHeader(protectedHeader)
                    .unprotectedHeader(new com.authlete.cose.COSEUnprotectedHeaderBuilder().build())
                    .payload(payload)
                    .signature(signature)
                    .build();
            return new com.authlete.cbor.CBORTaggedItem(18, sign1).encode();
        }

        private byte[] deflate(byte[] raw) {
            Deflater deflater = new Deflater();
            deflater.setInput(raw);
            deflater.finish();
            byte[] buffer = new byte[256];
            int length = deflater.deflate(buffer);
            deflater.end();
            return java.util.Arrays.copyOf(buffer, length);
        }

        private java.security.KeyPair ecKeyPair() throws Exception {
            java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
            generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        }

        private java.security.cert.X509Certificate certificate(
                java.security.KeyPair subject,
                java.security.KeyPair issuer,
                String subjectDn,
                String issuerDn,
                boolean ca)
                throws Exception {
            var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                    new javax.security.auth.x500.X500Principal(issuerDn),
                    java.math.BigInteger.valueOf(System.nanoTime()),
                    java.util.Date.from(Instant.now().minusSeconds(3600)),
                    java.util.Date.from(Instant.now().plusSeconds(86400)),
                    new javax.security.auth.x500.X500Principal(subjectDn),
                    subject.getPublic());
            builder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.basicConstraints,
                    true,
                    new org.bouncycastle.asn1.x509.BasicConstraints(ca));
            return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .getCertificate(builder.build(
                            new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                                    .build(issuer.getPrivate())));
        }
    }
}
