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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Verified presentations grouped by DCQL query ID, in request order. Claims stay separate. */
public record VpTokenResult(Map<String, List<VerifiedCredential>> credentials) {
    public VpTokenResult {
        Map<String, List<VerifiedCredential>> copy = new LinkedHashMap<>();
        credentials.forEach((id, values) -> copy.put(id, List.copyOf(values)));
        credentials = Collections.unmodifiableMap(copy);
    }

    public List<VerifiedCredential> allCredentials() {
        return credentials.values().stream().flatMap(List::stream).toList();
    }

    public VerifiedCredential getPrimaryCredential() {
        return allCredentials().stream().findFirst().orElse(null);
    }
}
