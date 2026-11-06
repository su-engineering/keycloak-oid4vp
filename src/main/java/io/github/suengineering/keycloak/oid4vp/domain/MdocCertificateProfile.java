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
package io.github.suengineering.keycloak.oid4vp.domain;

/** Which certificate profile mDoc issuer chains must follow beyond plain X.509 chain validation. */
public enum MdocCertificateProfile {
    /** Chain validation only. Fits PID and attestation providers that do not use the mDL profile. */
    NONE("none"),
    /** ISO/IEC 18013-5 Annex B: IACA root and document signer certificate profiles. */
    ISO_18013_5("iso18013-5");

    private final String configValue;

    MdocCertificateProfile(String configValue) {
        this.configValue = configValue;
    }

    public String configValue() {
        return configValue;
    }

    public static MdocCertificateProfile resolve(String value) {
        for (MdocCertificateProfile profile : values()) {
            if (profile.configValue.equalsIgnoreCase(value == null ? "" : value.trim())) return profile;
        }
        return NONE;
    }
}
