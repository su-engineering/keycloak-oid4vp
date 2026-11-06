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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * HPKE (RFC 9180) in base mode with the one suite ISO/IEC 18013-7 Annex C uses:
 * DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM. Single-shot only (sequence number 0).
 *
 * <p>Java 21 has no HPKE API, so this builds the scheme from JCA primitives. It is checked against
 * the RFC 9180 Appendix A.3 test vectors.
 */
public final class Hpke {

    private static final int KEM_ID = 0x0010;
    private static final int KDF_ID = 0x0001;
    private static final int AEAD_ID = 0x0001;
    private static final int N_SECRET = 32;
    private static final int N_KEY = 16;
    private static final int N_NONCE = 12;
    private static final int N_ENC = 65;
    private static final byte[] VERSION_LABEL = "HPKE-v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEM_SUITE_ID = concat(ascii("KEM"), i2osp(KEM_ID, 2));
    private static final byte[] HPKE_SUITE_ID =
            concat(ascii("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
    private static final ECParameterSpec P256 = p256();

    private Hpke() {}

    /** The sender's output: the encapsulated key and the AEAD ciphertext. */
    public record Sealed(byte[] enc, byte[] cipherText) {}

    /** Decrypts a single-shot message for the recipient key pair. */
    public static byte[] open(
            PrivateKey recipientPrivateKey,
            ECPublicKey recipientPublicKey,
            byte[] enc,
            byte[] info,
            byte[] aad,
            byte[] cipherText)
            throws GeneralSecurityException {
        if (enc == null || enc.length != N_ENC || enc[0] != 0x04) {
            throw new GeneralSecurityException("HPKE enc must be an uncompressed P-256 point");
        }
        byte[] dh = ecdh(recipientPrivateKey, decodePoint(enc));
        byte[] sharedSecret = extractAndExpand(dh, concat(enc, encodePoint(recipientPublicKey)));
        return aead(Cipher.DECRYPT_MODE, sharedSecret, info, aad, cipherText);
    }

    /** Encrypts a single-shot message to the recipient public key with a fresh ephemeral key. */
    public static Sealed seal(ECPublicKey recipientPublicKey, byte[] info, byte[] aad, byte[] plainText)
            throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(P256);
        KeyPair ephemeral = generator.generateKeyPair();
        byte[] enc = encodePoint((ECPublicKey) ephemeral.getPublic());
        byte[] dh = ecdh(ephemeral.getPrivate(), recipientPublicKey);
        byte[] sharedSecret = extractAndExpand(dh, concat(enc, encodePoint(recipientPublicKey)));
        return new Sealed(enc, aead(Cipher.ENCRYPT_MODE, sharedSecret, info, aad, plainText));
    }

    private static byte[] aead(int mode, byte[] sharedSecret, byte[] info, byte[] aad, byte[] input)
            throws GeneralSecurityException {
        // KeySchedule for mode_base: empty psk and psk_id.
        byte[] pskIdHash = labeledExtract(HPKE_SUITE_ID, new byte[0], "psk_id_hash", new byte[0]);
        byte[] infoHash = labeledExtract(HPKE_SUITE_ID, new byte[0], "info_hash", nullToEmpty(info));
        byte[] context = concat(new byte[] {0x00}, pskIdHash, infoHash);
        byte[] secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", new byte[0]);
        byte[] key = labeledExpand(HPKE_SUITE_ID, secret, "key", context, N_KEY);
        byte[] baseNonce = labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", context, N_NONCE);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, baseNonce));
        cipher.updateAAD(nullToEmpty(aad));
        return cipher.doFinal(input);
    }

    private static byte[] extractAndExpand(byte[] dh, byte[] kemContext) throws GeneralSecurityException {
        byte[] eaePrk = labeledExtract(KEM_SUITE_ID, new byte[0], "eae_prk", dh);
        return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, N_SECRET);
    }

    private static byte[] labeledExtract(byte[] suiteId, byte[] salt, String label, byte[] ikm)
            throws GeneralSecurityException {
        return hkdfExtract(salt, concat(VERSION_LABEL, suiteId, ascii(label), ikm));
    }

    private static byte[] labeledExpand(byte[] suiteId, byte[] prk, String label, byte[] info, int length)
            throws GeneralSecurityException {
        byte[] labeledInfo = concat(i2osp(length, 2), VERSION_LABEL, suiteId, ascii(label), info);
        return hkdfExpand(prk, labeledInfo, length);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        // RFC 5869: an absent salt is HashLen zero bytes.
        mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] block = new byte[0];
        for (int counter = 1; out.size() < length; counter++) {
            mac.update(block);
            mac.update(info);
            mac.update((byte) counter);
            block = mac.doFinal();
            out.writeBytes(block);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    private static byte[] ecdh(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret();
    }

    /** SerializePublicKey for P-256: the uncompressed SEC1 point. */
    public static byte[] encodePoint(ECPublicKey key) {
        return concat(
                new byte[] {0x04},
                unsigned(key.getW().getAffineX()),
                unsigned(key.getW().getAffineY()));
    }

    /** DeserializePublicKey for P-256 (RFC 9180 7.1.4: the point must be on the curve). */
    public static ECPublicKey decodePoint(byte[] encoded) throws GeneralSecurityException {
        if (encoded.length != N_ENC || encoded[0] != 0x04) {
            throw new GeneralSecurityException("Not an uncompressed P-256 point");
        }
        ECPoint point = new ECPoint(
                new BigInteger(1, Arrays.copyOfRange(encoded, 1, 33)),
                new BigInteger(1, Arrays.copyOfRange(encoded, 33, 65)));
        requireOnCurve(point);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, P256));
    }

    /** Rejects points off P-256; the JDK key factory does not check this. */
    private static void requireOnCurve(ECPoint point) throws GeneralSecurityException {
        java.security.spec.ECFieldFp field =
                (java.security.spec.ECFieldFp) P256.getCurve().getField();
        BigInteger p = field.getP();
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
            throw new GeneralSecurityException("P-256 point coordinates out of range");
        }
        BigInteger right = x.pow(3)
                .add(P256.getCurve().getA().multiply(x))
                .add(P256.getCurve().getB())
                .mod(p);
        if (!y.pow(2).mod(p).equals(right)) {
            throw new GeneralSecurityException("Point is not on P-256");
        }
    }

    public static ECParameterSpec p256Parameters() {
        return P256;
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] out = new byte[32];
        int length = Math.min(bytes.length, 32);
        System.arraycopy(bytes, bytes.length - length, out, 32 - length, length);
        return out;
    }

    private static ECParameterSpec p256() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 is not available", e);
        }
    }

    private static byte[] i2osp(int value, int length) {
        byte[] out = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            out[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        return out;
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] nullToEmpty(byte[] value) {
        return value == null ? new byte[0] : value;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
