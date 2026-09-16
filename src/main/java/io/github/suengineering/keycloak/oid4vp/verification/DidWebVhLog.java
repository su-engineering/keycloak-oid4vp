/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import static io.github.suengineering.keycloak.oid4vp.verification.DidWebVhResolver.require;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.decentralizedidentity.didwebvh.core.crypto.Base58Btc;
import io.github.decentralizedidentity.didwebvh.core.crypto.MultikeyUtil;
import io.github.decentralizedidentity.didwebvh.core.model.DataIntegrityProof;
import io.github.decentralizedidentity.didwebvh.core.model.JsonSupport;
import io.github.decentralizedidentity.didwebvh.core.model.LogEntry;
import io.github.decentralizedidentity.didwebvh.core.model.Parameters;
import io.github.decentralizedidentity.didwebvh.core.signing.ProofVerifier;
import io.github.decentralizedidentity.didwebvh.core.validate.LogChainValidator;
import io.github.decentralizedidentity.didwebvh.core.validate.WitnessValidator;
import io.github.decentralizedidentity.didwebvh.core.witness.WitnessProofCollection;
import io.github.decentralizedidentity.didwebvh.core.witness.WitnessProofEntry;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/** Strict input boundary around the pinned upstream v1.0 history and witness validators. */
final class DidWebVhLog {
    static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final int MAX_LOG_ENTRIES = 512;

    private DidWebVhLog() {}

    static ValidatedDocument validate(String did, String jsonl, Supplier<String> fetchWitness) throws Exception {
        bounded(jsonl);
        var expected = DidWebVhResolver.validateDid(did);
        List<LogEntry> entries = new ArrayList<>();
        Parameters active = Parameters.defaults();
        boolean needsWitness = false;
        String previousDid = null;
        for (String line : jsonl.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            require(entries.size() < MAX_LOG_ENTRIES, "DID history exceeds 512 entries");
            JsonNode raw = JSON.readTree(line);
            require(raw != null && raw.isObject(), "DID log entry must be an object");
            LogEntry entry = LogEntry.fromJsonLine(line);
            // Upstream uses typed models for hashing. Never allow fields or types to disappear/coerce.
            require(raw.equals(JSON.readTree(entry.toJsonLine())), "Unsupported fields or types in DID log entry");
            require(raw.path("parameters").isObject() && raw.path("state").isObject(), "Invalid DID log structure");
            Parameters next = active.merge(entry.getParameters());
            require("did:webvh:1.0".equals(next.getMethod()), "Only did:webvh:1.0 logs are supported");
            require(expected.getScid().equals(next.getScid()), "DID SCID does not match the log");
            require(next.getTtl() != null && next.getTtl() >= 0, "Invalid DID TTL");
            if (!entries.isEmpty()) {
                require(
                        !Boolean.TRUE.equals(entry.getParameters().getPortable()),
                        "Portability can only be enabled at creation");
            }
            String stateDid = raw.path("state").path("id").asText();
            require(
                    expected.getScid()
                            .equals(DidWebVhResolver.validateDid(stateDid).getScid()),
                    "DID state SCID changed");
            if (previousDid != null && !previousDid.equals(stateDid)) {
                require(Boolean.TRUE.equals(active.getPortable()), "DID moved without authorized portability");
                boolean linked = false;
                for (JsonNode alias : raw.path("state").path("alsoKnownAs")) {
                    linked |= previousDid.equals(alias.asText());
                }
                require(linked, "Moved DID must identify its previous DID in alsoKnownAs");
            }
            previousDid = stateDid;
            require(next.getUpdateKeys() != null && !next.getUpdateKeys().isEmpty(), "Missing update keys");
            for (String key : next.getUpdateKeys()) {
                require(MultikeyUtil.decode(key).length == 32, "Update key must be an Ed25519 multikey");
            }
            validateWitnessConfig(next);
            needsWitness |= next.getWitness() != null && next.getWitness().isActive();
            require(entry.getProof() != null && !entry.getProof().isEmpty(), "Missing DID log proof");
            boolean preRotation = !entries.isEmpty()
                    && active.getNextKeyHashes() != null
                    && !active.getNextKeyHashes().isEmpty();
            require(
                    !preRotation || entry.getParameters().getNextKeyHashes() != null,
                    "Pre-rotation update must explicitly set nextKeyHashes");
            List<String> signingKeys = entries.isEmpty() || preRotation ? next.getUpdateKeys() : active.getUpdateKeys();
            for (DataIntegrityProof proof : entry.getProof()) {
                validateProof(proof);
                require(
                        ProofVerifier.isAuthorized(proof, signingKeys) && ProofVerifier.verify(proof, entry),
                        "Invalid or unauthorized DID log proof");
            }
            entries.add(entry);
            active = next;
        }
        var validation = new LogChainValidator().validate(entries, did);
        require(validation.isValid(), "Invalid DID history: " + validation.getFailureReason());
        require(!Boolean.TRUE.equals(active.getDeactivated()), "Issuer DID is deactivated");
        require(did.equals(previousDid), "Issuer must use the current DID after a move");
        if (needsWitness) {
            validateWitnesses(entries, fetchWitness.get());
        }
        return new ValidatedDocument(JSON.readTree(entries.getLast().getState().toString()), active.getTtl());
    }

    private static void validateWitnessConfig(Parameters parameters) {
        var config = parameters.getWitness();
        if (config == null
                || (config.getThreshold() == 0 && config.getWitnesses().isEmpty())) {
            return;
        }
        Set<String> ids = new HashSet<>();
        for (var witness : config.getWitnesses()) {
            String id = witness.getId();
            require(id != null && id.startsWith("did:key:") && !id.contains("#"), "Invalid witness DID");
            require(MultikeyUtil.decode(id.substring(8)).length == 32, "Witness must use Ed25519");
            require(ids.add(id), "Duplicate witness DID");
        }
        require(config.getThreshold() > 0 && config.getThreshold() <= ids.size(), "Invalid witness threshold");
    }

    private static void validateWitnesses(List<LogEntry> entries, String json) throws Exception {
        bounded(json);
        JsonNode raw = JSON.readTree(json);
        require(raw != null && raw.isArray(), "Witness proofs must be a JSON array");
        List<WitnessProofEntry> proofs = new ArrayList<>();
        Set<String> versions = new HashSet<>();
        entries.forEach(entry -> versions.add(entry.getVersionId()));
        for (JsonNode item : raw) {
            require(item.isObject(), "Invalid witness proof entry");
            WitnessProofEntry entry = JsonSupport.compact().fromJson(item.toString(), WitnessProofEntry.class);
            require(
                    item.equals(JSON.readTree(JsonSupport.compact().toJson(entry))),
                    "Unsupported witness fields or types");
            // Proofs for unpublished versions do not approve this history.
            if (!versions.contains(entry.getVersionId())) {
                continue;
            }
            require(entry.getProof() != null && !entry.getProof().isEmpty(), "Missing witness proof");
            for (DataIntegrityProof proof : entry.getProof()) {
                validateProof(proof);
            }
            proofs.add(entry);
        }
        var result = new WitnessValidator().validate(entries, new WitnessProofCollection(proofs), 0);
        require(result.isValid(), "Invalid DID witnesses: " + result.getFailureReason());
    }

    private static void validateProof(DataIntegrityProof proof) {
        require(
                proof != null
                        && "DataIntegrityProof".equals(proof.getType())
                        && "eddsa-jcs-2022".equals(proof.getCryptosuite())
                        && "assertionMethod".equals(proof.getProofPurpose()),
                "Unsupported DID proof type, cryptosuite or purpose");
        String reference = proof.getVerificationMethod();
        require(reference != null && reference.startsWith("did:key:"), "Proof key must be a did:key reference");
        String[] parts = reference.substring(8).split("#", -1);
        require(parts.length == 2 && parts[0].equals(parts[1]), "Proof key body and fragment must match");
        require(MultikeyUtil.decode(parts[0]).length == 32, "Proof key must be Ed25519");
        require(
                proof.getProofValue() != null && Base58Btc.decodeMultibase(proof.getProofValue()).length == 64,
                "Invalid DID proof signature length");
        if (proof.getCreated() != null) {
            Instant.parse(proof.getCreated());
        }
    }

    private static void bounded(String body) {
        require(body != null && !body.isBlank(), "Missing DID artifact");
        require(
                body.getBytes(StandardCharsets.UTF_8).length <= DidWebVhResolver.MAX_RESPONSE_BYTES,
                "DID artifact exceeds 1 MiB");
    }

    record ValidatedDocument(JsonNode document, long ttl) {}
}
