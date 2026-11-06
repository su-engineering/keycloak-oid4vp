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

import org.keycloak.utils.StringUtil;

/**
 * Models the OID4VP response modes used by the verifier.
 *
 * <p>The direct-post modes serve the redirect flows (same-device and cross-device). The
 * {@code dc_api} modes serve the browser Digital Credentials API flow and are derived from the
 * configured direct-post mode, never configured on their own.
 */
public enum Oid4vpResponseMode {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt"),
    DC_API("dc_api"),
    DC_API_JWT("dc_api.jwt");

    private final String parameterValue;

    Oid4vpResponseMode(String parameterValue) {
        this.parameterValue = parameterValue;
    }

    public String parameterValue() {
        return parameterValue;
    }

    public boolean requiresEncryption() {
        return this == DIRECT_POST_JWT || this == DC_API_JWT;
    }

    public boolean isDcApi() {
        return this == DC_API || this == DC_API_JWT;
    }

    /** Returns the Digital Credentials API mode with the same encryption requirement. */
    public Oid4vpResponseMode forDcApi() {
        return requiresEncryption() ? DC_API_JWT : DC_API;
    }

    public static Oid4vpResponseMode resolve(String rawValue, boolean enforceHaip) {
        return enforceHaip ? DIRECT_POST_JWT : resolve(rawValue);
    }

    /** Resolves a configured redirect-flow response mode; unknown and dc_api values fall back to direct_post. */
    public static Oid4vpResponseMode resolve(String rawValue) {
        if (StringUtil.isBlank(rawValue)) {
            return DIRECT_POST;
        }
        if (DIRECT_POST_JWT.parameterValue.equalsIgnoreCase(rawValue)) {
            return DIRECT_POST_JWT;
        }
        return DIRECT_POST;
    }
}
