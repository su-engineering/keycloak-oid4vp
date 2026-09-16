/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.decentralizedidentity.didwebvh.core.crypto.Base58Btc;
import java.util.HexFormat;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class WebVhBase58Test {
    @ParameterizedTest
    @CsvSource({
        "'',''",
        "00,1",
        "0000,11",
        "61,2g",
        "626262,a3gV",
        "636363,aPEr",
        "68656c6c6f20776f726c64,StV1DL6CwTryKyV"
    })
    void matchesKnownBase58BtcVectors(String hex, String encoded) {
        byte[] decoded = HexFormat.of().parseHex(hex);
        assertThat(Base58Btc.encode(decoded)).isEqualTo(encoded);
        assertThat(Base58Btc.decode(encoded)).isEqualTo(decoded);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "O", "I", "l", " "})
    void rejectsCharactersOutsideTheBitcoinAlphabet(String encoded) {
        assertThatThrownBy(() -> Base58Btc.decode(encoded)).isInstanceOf(IllegalArgumentException.class);
    }
}
