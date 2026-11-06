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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.keycloak.oid4vp.verification.IsoMdocDcApi;
import io.github.suengineering.keycloak.oid4vp.verification.MdocVerifier;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class CborLimitsTest {

    private static byte[] nested(int depth) {
        byte[] bytes = new byte[depth + 1];
        Arrays.fill(bytes, 0, depth, (byte) 0x81); // array of one item, repeated
        bytes[depth] = 0x00;
        return bytes;
    }

    @Test
    void rejectsDeepNestingWithoutRecursing() {
        assertThatThrownBy(() -> CborLimits.check(nested(10_000))).hasMessageContaining("nested deeper");
        assertThatCode(() -> CborLimits.check(nested(CborLimits.MAX_DEPTH))).doesNotThrowAnyException();
    }

    @Test
    void rejectsTruncationAndOversizedLengths() {
        assertThatThrownBy(() -> CborLimits.check(HexFormat.of().parseHex("820118")))
                .hasMessageContaining("Truncated");
        assertThatThrownBy(() -> CborLimits.check(HexFormat.of().parseHex("5affffffff00")))
                .hasMessageContaining("longer than input");
        assertThatThrownBy(() -> CborLimits.check(HexFormat.of().parseHex("9b00000000ffffffff")))
                .hasMessageContaining("larger than input");
    }

    @Test
    void acceptsOrdinaryStructures() {
        // {"a": [1, 2, h'00'], "b": 24(<<{}>>)} plus an indefinite array terminated by break
        assertThatCode(() -> CborLimits.check(HexFormat.of().parseHex("a2616183010241006162d81841a0")))
                .doesNotThrowAnyException();
        assertThatCode(() -> CborLimits.check(HexFormat.of().parseHex("9f0102ff")))
                .doesNotThrowAnyException();
    }

    @Test
    void entryPointsRejectDeepCborInsteadOfOverflowingTheStack() {
        String deep = Base64.getUrlEncoder().withoutPadding().encodeToString(nested(10_000));

        assertThat(new MdocVerifier().isMdoc(deep)).isFalse();
        assertThatThrownBy(() -> IsoMdocDcApi.openResponse(
                        deep, new IsoMdocDcApi.PreparedRequest(null, "x", "{}"), "https://rp.example", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
