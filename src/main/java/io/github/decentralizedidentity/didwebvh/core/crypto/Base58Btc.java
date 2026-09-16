/*
 * Copyright 2026 Bundesagentur für Arbeit
 * Copyright 2026 su-engineering
 * SPDX-License-Identifier: Apache-2.0
 * Decoder adapted from this project's DidWebResolver; encoder and adapter by su-engineering.
 */
package io.github.decentralizedidentity.didwebvh.core.crypto;

import java.math.BigInteger;

/**
 * Apache-2.0 replacement for the didwebvh-core 0.3.1 Base58 facade. The upstream facade delegates
 * to a GPL dependency; that dependency and facade are excluded from our shaded JAR. This small
 * adapter preserves the upstream API using the encoding algorithm already used in DidWebResolver.
 * Keep its package/API and the Maven shade exclusion in sync when upgrading didwebvh-core.
 */
public final class Base58Btc {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger RADIX = BigInteger.valueOf(58);

    private Base58Btc() {}

    public static String encode(byte[] data) {
        if (data.length == 0) {
            return "";
        }
        int zeros = 0;
        while (zeros < data.length && data[zeros] == 0) {
            zeros++;
        }
        StringBuilder encoded = new StringBuilder();
        BigInteger value = new BigInteger(1, data);
        while (value.signum() > 0) {
            BigInteger[] parts = value.divideAndRemainder(RADIX);
            encoded.append(ALPHABET.charAt(parts[1].intValue()));
            value = parts[0];
        }
        encoded.append("1".repeat(zeros));
        return encoded.reverse().toString();
    }

    public static byte[] decode(String encoded) {
        int zeros = 0;
        while (zeros < encoded.length() && encoded.charAt(zeros) == '1') {
            zeros++;
        }
        BigInteger value = BigInteger.ZERO;
        for (int i = 0; i < encoded.length(); i++) {
            int digit = ALPHABET.indexOf(encoded.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid base58btc character");
            }
            value = value.multiply(RADIX).add(BigInteger.valueOf(digit));
        }
        byte[] magnitude = value.signum() == 0 ? new byte[0] : value.toByteArray();
        int offset = magnitude.length > 0 && magnitude[0] == 0 ? 1 : 0;
        byte[] result = new byte[zeros + magnitude.length - offset];
        System.arraycopy(magnitude, offset, result, zeros, magnitude.length - offset);
        return result;
    }

    public static String encodeMultibase(byte[] data) {
        return "z" + encode(data);
    }

    public static byte[] decodeMultibase(String multibase) {
        if (multibase == null || !multibase.startsWith("z") || multibase.length() < 2) {
            throw new IllegalArgumentException("Expected base58btc multibase value");
        }
        return decode(multibase.substring(1));
    }
}
