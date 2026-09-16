/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import com.google.gson.JsonObject;
import io.github.decentralizedidentity.didwebvh.core.crypto.Base58Btc;
import io.github.decentralizedidentity.didwebvh.core.crypto.EntryHashGenerator;
import io.github.decentralizedidentity.didwebvh.core.crypto.MultikeyUtil;
import io.github.decentralizedidentity.didwebvh.core.crypto.ScidGenerator;
import io.github.decentralizedidentity.didwebvh.core.model.DataIntegrityProof;
import io.github.decentralizedidentity.didwebvh.core.model.JsonSupport;
import io.github.decentralizedidentity.didwebvh.core.model.LogEntry;
import io.github.decentralizedidentity.didwebvh.core.model.Parameters;
import io.github.decentralizedidentity.didwebvh.core.signing.ProofGenerator;
import io.github.decentralizedidentity.didwebvh.core.signing.Signer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/** Synthetic log updates use a separate controller key from the credential issuer's key. */
final class WebVhTestLog {
    final TestSigner controller = new TestSigner();
    final List<LogEntry> entries = new ArrayList<>();
    final String did;

    WebVhTestLog(JsonObject assertionKey) {
        this(assertionKey, p -> {});
    }

    WebVhTestLog(JsonObject assertionKey, Consumer<Parameters> configure) {
        Parameters params = new Parameters()
                .setMethod("did:webvh:1.0")
                .setScid("{SCID}")
                .setUpdateKeys(List.of(controller.multikey()))
                .setPortable(false)
                .setTtl(30);
        configure.accept(params);
        LogEntry entry = new LogEntry()
                .setVersionId("{SCID}")
                .setVersionTime("2026-01-01T00:00:00Z")
                .setParameters(params)
                .setState(document("did:webvh:{SCID}:issuer.example", assertionKey));
        String scid = ScidGenerator.generate(entry);
        entry = LogEntry.fromJsonLine(entry.toJsonLine().replace("{SCID}", scid));
        entry.setVersionId("1-" + EntryHashGenerator.generate(entry.toJsonLine(), scid));
        entry.setProof(List.of(ProofGenerator.generate(controller, entry)));
        entries.add(entry);
        did = entry.getState().get("id").getAsString();
    }

    void append(JsonObject state, Parameters params, TestSigner signer) {
        LogEntry previous = entries.getLast();
        LogEntry entry = new LogEntry()
                .setVersionId(previous.getVersionId())
                .setVersionTime(
                        Instant.parse(previous.getVersionTime()).plusSeconds(60).toString())
                .setParameters(params)
                .setState(state);
        entry.setVersionId(
                (entries.size() + 1) + "-" + EntryHashGenerator.generate(entry.toJsonLine(), previous.getVersionId()));
        entry.setProof(List.of(ProofGenerator.generate(signer, entry)));
        entries.add(entry);
    }

    String jsonl() {
        return entries.stream().map(LogEntry::toJsonLine).collect(Collectors.joining("\n"));
    }

    static JsonObject document(String did, JsonObject assertionKey) {
        JsonObject method = new JsonObject();
        method.addProperty("id", did + "#issuer-key");
        method.addProperty("controller", did);
        if (assertionKey.has("kty")) {
            method.addProperty("type", "JsonWebKey2020");
            method.add("publicKeyJwk", assertionKey);
        } else {
            method.addProperty("type", "Multikey");
            method.add("publicKeyMultibase", assertionKey.get("publicKeyMultibase"));
        }
        JsonObject document = new JsonObject();
        document.addProperty("id", did);
        document.add("verificationMethod", JsonSupport.compact().toJsonTree(List.of(method)));
        document.add("assertionMethod", JsonSupport.compact().toJsonTree(List.of(did + "#issuer-key")));
        return document;
    }

    static final class TestSigner implements Signer {
        final KeyPair keys;

        TestSigner() {
            try {
                keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        String multikey() {
            byte[] encoded = keys.getPublic().getEncoded();
            return MultikeyUtil.encode("Ed25519", Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
        }

        JsonObject publicKey() {
            JsonObject key = new JsonObject();
            key.addProperty("publicKeyMultibase", multikey());
            return key;
        }

        public String keyType() {
            return "Ed25519";
        }

        public String verificationMethod() {
            return "did:key:" + multikey() + "#" + multikey();
        }

        public byte[] sign(byte[] data) {
            try {
                Signature signature = Signature.getInstance("Ed25519");
                signature.initSign(keys.getPrivate());
                signature.update(data);
                return signature.sign();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        void signProof(DataIntegrityProof proof, JsonObject document) {
            proof.setProofValue(Base58Btc.encodeMultibase(sign(ProofGenerator.buildHashData(proof, document))));
        }
    }
}
