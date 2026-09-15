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
package io.github.suengineering.keycloak.oid4vp.verification;

import java.util.List;
import org.keycloak.crypto.SignatureVerifierContext;

/**
 * Strategy interface for resolving DID documents and extracting verification contexts.
 *
 * <p>Implementations resolve a DID (Decentralized Identifier) and extract the cryptographic
 * verification material needed for signature verification. This enables pluggable DID method
 * support (e.g., did:web, did:key, did:jwk) for credential verification.
 *
 * <p>The resolution process typically involves:
 * <ol>
 *   <li>Dereferencing the DID document from the DID method's resolution endpoint</li>
 *   <li>Extracting the verification method identified by the keyId</li>
 *   <li>Converting the verification material to Keycloak's {@link SignatureVerifierContext}</li>
 * </ol>
 *
 * <p>Implementations should handle caching internally to avoid repeated network requests
 * for the same DID document.
 *
 * @since 1.1.0
 * @see SignatureVerifierContext
 */
public interface DidResolver {

    /**
     * Resolves a DID and extracts verification contexts for the specified key.
     *
     * <p>The keyId parameter identifies which verification method within the DID document
     * to use. If the keyId is {@code null} or empty, implementations may return all
     * available verification contexts or use a default selection strategy.
     *
     * @param did the decentralized identifier to resolve (e.g., "did:web:example.com")
     * @param keyId the key identifier fragment within the DID document (e.g., "#key-1"),
     *     may be {@code null} to use default key selection
     * @return a list of signature verifier contexts for the resolved keys, empty list
     *     if resolution fails or no matching keys found
     * @throws IllegalArgumentException if the DID format is invalid
     */
    List<SignatureVerifierContext> resolve(String did, String keyId);

    /**
     * Checks whether this resolver supports the given DID method.
     *
     * <p>Implementations should return {@code true} only for DID methods they can
     * successfully resolve. For example, a did:web resolver would return {@code true}
     * for "did:web:example.com" but {@code false} for "did:key:z6Mk...".
     *
     * @param did the decentralized identifier to check
     * @return {@code true} if this resolver can handle the DID method, {@code false} otherwise
     */
    boolean supports(String did);
}
