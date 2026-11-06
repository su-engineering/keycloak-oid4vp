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

import java.net.InetAddress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OutboundUrlPolicyTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/statuslist",
                "http://10.0.0.5:6379/",
                "http://172.16.1.1/",
                "http://192.168.1.1/",
                "http://169.254.169.254/latest/meta-data/",
                "http://100.64.0.1/",
                "http://0.0.0.0/",
                "http://[::1]/",
                "http://[fd00::1]/",
                "http://[::ffff:127.0.0.1]/",
                "http://localhost/"
            })
    void refusesNonPublicAddresses(String url) {
        assertThatThrownBy(() -> OutboundUrlPolicy.check(url, false)).hasMessageContaining("private or local");
    }

    @Test
    void refusesOtherSchemesAndUserInfo() {
        assertThatThrownBy(() -> OutboundUrlPolicy.check("file:///etc/passwd", true))
                .hasMessageContaining("non-HTTP");
        assertThatThrownBy(() -> OutboundUrlPolicy.check("https://a.example@10.0.0.1/", true))
                .hasMessageContaining("plain host");
    }

    @Test
    void privateAddressesPassWhenAllowed() {
        assertThatCode(() -> OutboundUrlPolicy.check("http://10.0.0.5/", true)).doesNotThrowAnyException();
    }

    @Test
    void publicAddressesPass() throws Exception {
        assertThat(OutboundUrlPolicy.isPublic(InetAddress.getByName("93.184.215.14")))
                .isTrue();
        assertThat(OutboundUrlPolicy.isPublic(InetAddress.getByName("2606:4700::1111")))
                .isTrue();
    }
}
