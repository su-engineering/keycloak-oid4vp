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
package io.github.suengineering.keycloak.oid4vp.domain;

import java.util.List;
import java.util.Map;
import org.keycloak.crypto.SignatureVerifierContext;

/**
 * Result of verifying an SD-JWT Verifiable Credential presented in a {@code vp_token}.
 *
 * <p>Contains the disclosed claims after selective disclosure resolution, the issuer identifier,
 * and the credential type (VCT). Produced by {@link io.github.suengineering.keycloak.oid4vp.verification.SdJwtVerifier}.
 */
public record SdJwtVerificationResult(
        Map<String, Object> claims,
        String issuer,
        String credentialType,
        Map<String, Object> issuerSignedClaims,
        List<SignatureVerifierContext> issuerVerifiers) {

    /**
     * @param issuerSignedClaims the issuer-signed payload before disclosures are applied; used for
     *     claims that must not be selectively disclosable, such as {@code status}
     * @param issuerVerifiers the verifier contexts that were authorized for the issuer's signature;
     *     a status list token may be verified with the same keys
     */
    public SdJwtVerificationResult {
        issuerSignedClaims = issuerSignedClaims != null ? issuerSignedClaims : Map.of();
        issuerVerifiers = issuerVerifiers != null ? List.copyOf(issuerVerifiers) : List.of();
    }

    public SdJwtVerificationResult(Map<String, Object> claims, String issuer, String credentialType) {
        this(claims, issuer, credentialType, claims, List.of());
    }
}
