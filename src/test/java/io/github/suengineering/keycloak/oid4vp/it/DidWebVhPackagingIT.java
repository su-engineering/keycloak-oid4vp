/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.it;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.decentralizedidentity.didwebvh.core.crypto.Base58Btc;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;

/** Runs after shading; prevents accidentally reintroducing the upstream GPL-backed Base58 facade. */
class DidWebVhPackagingIT {
    @Test
    void packagesOnlyOurBase58AdapterAndExpectedDependencies() throws Exception {
        String adapter = "io/github/decentralizedidentity/didwebvh/core/crypto/Base58Btc.class";
        try (var jar = new ZipFile(
                        Path.of("target/keycloak-extension-oid4vp.jar").toFile());
                var compiled = Base58Btc.class.getResourceAsStream("/" + adapter)) {
            assertThat(jar.stream().filter(entry -> entry.getName().equals(adapter)))
                    .hasSize(1);
            byte[] bundled = jar.getInputStream(jar.getEntry(adapter)).readAllBytes();
            assertThat(bundled).isEqualTo(compiled.readAllBytes());
            assertThat(new String(bundled, StandardCharsets.ISO_8859_1)).doesNotContain("novacrypto");
            assertThat(jar.stream().map(entry -> entry.getName()))
                    .noneMatch(name -> name.startsWith("io/github/novacrypto/")
                            || name.startsWith("okhttp3/")
                            || name.startsWith("com/google/gson/")
                            || name.startsWith("org/bouncycastle/"));
            assertThat(jar.getEntry("io/github/decentralizedidentity/didwebvh/core/validate/LogChainValidator.class"))
                    .isNotNull();
            assertThat(jar.getEntry("org/erdtman/jcs/JsonCanonicalizer.class")).isNotNull();
        }
    }
}
