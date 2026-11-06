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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class HpkeTest {

    private static final HexFormat HEX = HexFormat.of();

    // RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, mode_base.
    private static final String INFO = "4f6465206f6e2061204772656369616e2055726e";
    private static final String SK_RM = "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";
    private static final String PK_RM = "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70"
            + "6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";
    private static final String ENC = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325"
            + "ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";
    private static final String PT = "4265617574792069732074727574682c20747275746820626561757479";
    private static final String AAD_0 = "436f756e742d30";
    private static final String CT_0 =
            "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f" + "9076ac232e3ab2523f39513434";

    @Test
    void open_matchesTheRfc9180Vector() throws Exception {
        byte[] plainText = Hpke.open(
                recipientPrivateKey(),
                Hpke.decodePoint(HEX.parseHex(PK_RM)),
                HEX.parseHex(ENC),
                HEX.parseHex(INFO),
                HEX.parseHex(AAD_0),
                HEX.parseHex(CT_0));

        assertThat(HEX.formatHex(plainText)).isEqualTo(PT);
    }

    @Test
    void open_rejectsAWrongInfo() throws Exception {
        assertThatThrownBy(() -> Hpke.open(
                        recipientPrivateKey(),
                        Hpke.decodePoint(HEX.parseHex(PK_RM)),
                        HEX.parseHex(ENC),
                        "other".getBytes(StandardCharsets.US_ASCII),
                        HEX.parseHex(AAD_0),
                        HEX.parseHex(CT_0)))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void sealThenOpen_roundTrips() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(Hpke.p256Parameters());
        KeyPair recipient = generator.generateKeyPair();
        byte[] info = "transcript".getBytes(StandardCharsets.US_ASCII);

        Hpke.Sealed sealed = Hpke.seal((ECPublicKey) recipient.getPublic(), info, new byte[0], HEX.parseHex(PT));

        assertThat(sealed.enc()).hasSize(65);
        assertThat(Hpke.open(
                        recipient.getPrivate(),
                        (ECPublicKey) recipient.getPublic(),
                        sealed.enc(),
                        info,
                        new byte[0],
                        sealed.cipherText()))
                .isEqualTo(HEX.parseHex(PT));
    }

    @Test
    void decodePoint_rejectsPointsOffTheCurve() {
        byte[] bad = HEX.parseHex(PK_RM);
        bad[64] ^= 0x01;

        assertThatThrownBy(() -> Hpke.decodePoint(bad)).isInstanceOf(Exception.class);
    }

    private static PrivateKey recipientPrivateKey() throws Exception {
        return KeyFactory.getInstance("EC")
                .generatePrivate(new ECPrivateKeySpec(new BigInteger(1, HEX.parseHex(SK_RM)), Hpke.p256Parameters()));
    }
}
