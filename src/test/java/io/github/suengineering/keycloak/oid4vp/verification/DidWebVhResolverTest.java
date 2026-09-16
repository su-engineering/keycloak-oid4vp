/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.google.gson.JsonObject;
import io.github.decentralizedidentity.didwebvh.core.crypto.PreRotationHashGenerator;
import io.github.decentralizedidentity.didwebvh.core.model.DataIntegrityProof;
import io.github.decentralizedidentity.didwebvh.core.model.JsonSupport;
import io.github.decentralizedidentity.didwebvh.core.model.Parameters;
import io.github.decentralizedidentity.didwebvh.core.witness.WitnessConfig;
import io.github.decentralizedidentity.didwebvh.core.witness.WitnessEntry;
import io.github.decentralizedidentity.didwebvh.core.witness.WitnessProofEntry;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicStatusLine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

class DidWebVhResolverTest {
    @BeforeAll
    static void crypto() {
        CryptoIntegration.init(DidWebVhResolverTest.class.getClassLoader());
    }

    @Test
    void resolvesCurrentAssertionKeyAndChecksKidOnCachedDocuments() throws Exception {
        var issuer = new WebVhTestLog.TestSigner();
        var log = new WebVhTestLog(issuer.publicKey());
        AtomicInteger fetches = new AtomicInteger();
        var resolver = resolver(url -> {
            fetches.incrementAndGet();
            return log.jsonl();
        });
        byte[] message = "credential".getBytes(StandardCharsets.UTF_8);
        assertThat(resolver.resolve(log.did, "#issuer-key").getFirst().verify(message, issuer.sign(message)))
                .isTrue();
        assertThat(resolver.resolve(log.did, log.did + "#issuer-key")).hasSize(1);
        assertThatThrownBy(() -> resolver.resolve(log.did, "#wrong")).hasMessageContaining("kid");
        assertThatThrownBy(() -> resolver.resolve(log.did, "did:web:attacker.example#issuer-key"))
                .hasMessageContaining("fragment");
        assertThat(fetches).hasValue(1);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "tampered",
                "unknown-field",
                "duplicate-field",
                "bad-hash",
                "unsupported-version",
                "wrong-suite",
                "wrong-purpose",
                "mismatched-proof-key",
                "authentication-only",
                "wrong-controller",
                "deactivated",
                "unauthorized-update",
                "broken-chain"
            })
    void rejectsInvalidHistoryOrUnauthorizedKeys(String scenario) {
        var issuer = new WebVhTestLog.TestSigner();
        var log = new WebVhTestLog(issuer.publicKey());
        var state = log.entries.getLast().getState().deepCopy();
        switch (scenario) {
            case "authentication-only" -> {
                state.remove("assertionMethod");
                log.append(state, new Parameters(), log.controller);
            }
            case "wrong-controller" -> {
                state.getAsJsonArray("verificationMethod")
                        .get(0)
                        .getAsJsonObject()
                        .addProperty("controller", "did:web:other.example");
                log.append(state, new Parameters(), log.controller);
            }
            case "deactivated" -> log.append(state, new Parameters().setDeactivated(true), log.controller);
            case "unauthorized-update" -> log.append(state, new Parameters(), issuer);
            case "unsupported-version" ->
                log.append(state, new Parameters().setMethod("did:webvh:2.0"), log.controller);
            case "broken-chain" -> {
                log.append(state, new Parameters(), log.controller);
                log.entries.removeFirst();
            }
            default -> {}
        }
        var proof = log.entries.getLast().getProof().getFirst();
        if (scenario.equals("wrong-suite")
                || scenario.equals("wrong-purpose")
                || scenario.equals("mismatched-proof-key")) {
            switch (scenario) {
                case "wrong-suite" -> proof.setCryptosuite("ecdsa-jcs-2019");
                case "wrong-purpose" -> proof.setProofPurpose("authentication");
                case "mismatched-proof-key" ->
                    proof.setVerificationMethod("did:key:" + issuer.multikey() + "#" + log.controller.multikey());
            }
            JsonObject unsigned =
                    JsonSupport.compact().toJsonTree(log.entries.getLast()).getAsJsonObject();
            unsigned.remove("proof");
            log.controller.signProof(proof, unsigned); // Even a cryptographically valid wrong-suite proof must fail.
        }
        String body =
                switch (scenario) {
                    case "tampered" -> log.jsonl().replace("issuer-key", "attacker-key");
                    case "unknown-field" ->
                        log.jsonl().replace("\"parameters\":{", "\"parameters\":{\"futureSecurityRule\":true,");
                    case "duplicate-field" -> log.jsonl().replace("\"ttl\":30", "\"ttl\":30,\"ttl\":30");
                    case "bad-hash" -> log.jsonl().replace("\"versionId\":\"1-", "\"versionId\":\"1-x");
                    default -> log.jsonl();
                };
        assertThatThrownBy(() -> resolver(url -> body).resolve(log.did, null))
                .isInstanceOf(DidResolutionException.class);
    }

    @Test
    void checksScidAgainstRequestedDid() {
        var key = new WebVhTestLog.TestSigner();
        var log = new WebVhTestLog(key.publicKey());
        var other = new WebVhTestLog(key.publicKey());
        assertThatThrownBy(() -> resolver(url -> log.jsonl()).resolve(other.did, null))
                .hasMessageContaining("SCID");
    }

    @Test
    void keyRotationUsesOnlyCurrentCredentialKeyAndHonorsPreRotationCommitments() throws Exception {
        var before = new WebVhTestLog.TestSigner();
        var after = new WebVhTestLog.TestSigner();
        var nextController = new WebVhTestLog.TestSigner();
        var log = new WebVhTestLog(
                before.publicKey(),
                p -> p.setNextKeyHashes(List.of(PreRotationHashGenerator.generateHash(nextController.multikey()))));
        log.append(
                WebVhTestLog.document(log.did, after.publicKey()),
                new Parameters()
                        .setUpdateKeys(List.of(nextController.multikey()))
                        .setNextKeyHashes(List.of()),
                nextController);
        var key = resolver(url -> log.jsonl()).resolve(log.did, null).getFirst();
        byte[] data = {1, 2, 3};
        assertThat(key.verify(data, after.sign(data))).isTrue();
        assertThat(key.verify(data, before.sign(data))).isFalse();
    }

    @Test
    void requiresWitnessQuorumAndRejectsReplayedProofs() {
        var witness = new WebVhTestLog.TestSigner();
        var log = new WebVhTestLog(
                witness.publicKey(),
                p -> p.setWitness(new WitnessConfig(1, List.of(new WitnessEntry("did:key:" + witness.multikey())))));
        DataIntegrityProof proof = DataIntegrityProof.defaults().setVerificationMethod(witness.verificationMethod());
        JsonObject document = new JsonObject();
        document.addProperty("versionId", log.entries.getFirst().getVersionId());
        witness.signProof(proof, document);
        String witnessed = JsonSupport.compact()
                .toJson(List.of(new WitnessProofEntry(log.entries.getFirst().getVersionId(), List.of(proof))));
        assertThat(resolver(url -> url.endsWith("did.jsonl") ? log.jsonl() : witnessed)
                        .resolve(log.did, null))
                .hasSize(1);
        assertThatThrownBy(() -> resolver(url -> url.endsWith("did.jsonl") ? log.jsonl() : "[]")
                        .resolve(log.did, null))
                .hasMessageContaining("witness");
        String replayed = witnessed.replace(log.entries.getFirst().getVersionId(), "1-unpublished");
        assertThatThrownBy(() -> resolver(url -> url.endsWith("did.jsonl") ? log.jsonl() : replayed)
                        .resolve(log.did, null))
                .hasMessageContaining("witness");
    }

    @Test
    void honorsLogTtlAndNeverUsesStaleDocumentOnFetchFailure() {
        var log = new WebVhTestLog(new WebVhTestLog.TestSigner().publicKey());
        Clock clock = mock(Clock.class);
        Instant start = Instant.parse("2026-09-16T00:00:00Z");
        when(clock.instant()).thenReturn(start);
        AtomicInteger fetches = new AtomicInteger();
        var resolver = new DidWebVhResolver(
                url -> {
                    if (fetches.incrementAndGet() > 1) throw new IllegalStateException("offline");
                    return log.jsonl();
                },
                3600,
                clock);
        resolver.resolve(log.did, null);
        when(clock.instant()).thenReturn(start.plusSeconds(29));
        resolver.resolve(log.did, null);
        when(clock.instant()).thenReturn(start.plusSeconds(30));
        assertThatThrownBy(() -> resolver.resolve(log.did, null)).isInstanceOf(DidResolutionException.class);
        assertThat(fetches).hasValue(2);
    }

    @Test
    void reducingWitnessThresholdStillRequiresThePreviousWitnesses() {
        var first = new WebVhTestLog.TestSigner();
        var second = new WebVhTestLog.TestSigner();
        var log = new WebVhTestLog(
                first.publicKey(),
                p -> p.setWitness(new WitnessConfig(
                        2,
                        List.of(
                                new WitnessEntry("did:key:" + first.multikey()),
                                new WitnessEntry("did:key:" + second.multikey())))));
        log.append(
                log.entries.getFirst().getState(),
                new Parameters()
                        .setWitness(new WitnessConfig(1, List.of(new WitnessEntry("did:key:" + first.multikey())))),
                log.controller);
        String version = log.entries.getLast().getVersionId();
        JsonObject document = new JsonObject();
        document.addProperty("versionId", version);
        DataIntegrityProof p1 = DataIntegrityProof.defaults().setVerificationMethod(first.verificationMethod());
        DataIntegrityProof p2 = DataIntegrityProof.defaults().setVerificationMethod(second.verificationMethod());
        first.signProof(p1, document);
        second.signProof(p2, document);
        for (List<DataIntegrityProof> insufficient : List.of(List.of(p1), List.of(p1, p1))) {
            String witnesses = JsonSupport.compact().toJson(List.of(new WitnessProofEntry(version, insufficient)));
            assertThatThrownBy(() -> resolver(url -> url.endsWith("did.jsonl") ? log.jsonl() : witnesses)
                            .resolve(log.did, null))
                    .hasMessageContaining("witness");
        }
        // The two latest proofs also attest to the prior entry, without retaining old proofs.
        String witnesses = JsonSupport.compact().toJson(List.of(new WitnessProofEntry(version, List.of(p1, p2))));
        assertThat(resolver(url -> url.endsWith("did.jsonl") ? log.jsonl() : witnesses)
                        .resolve(log.did, null))
                .hasSize(1);
    }

    @Test
    void validatesPortableMovesAndRequiresTheCurrentIssuerDid() {
        var key = new WebVhTestLog.TestSigner();
        var log = new WebVhTestLog(key.publicKey(), p -> p.setPortable(true));
        String movedDid = log.did.replace("issuer.example", "new.example:credentials");
        JsonObject state = WebVhTestLog.document(movedDid, key.publicKey());
        state.add("alsoKnownAs", JsonSupport.compact().toJsonTree(List.of(log.did)));
        log.append(state, new Parameters(), log.controller);
        assertThat(resolver(url -> {
                            assertThat(url).isEqualTo("https://new.example/credentials/did.jsonl");
                            return log.jsonl();
                        })
                        .resolve(movedDid, null))
                .hasSize(1);
        assertThatThrownBy(() -> resolver(url -> log.jsonl()).resolve(log.did, null))
                .hasMessageContaining("current DID");
    }

    @ParameterizedTest
    @ValueSource(strings = {"?versionNumber=1", "#issuer-key", ":.."})
    void rejectsHistoricalIssuerUrlsAndDotPathsBeforeFetching(String suffix) {
        var log = new WebVhTestLog(new WebVhTestLog.TestSigner().publicKey());
        assertThatThrownBy(() -> resolver(url -> {
                            throw new AssertionError("must not fetch");
                        })
                        .resolve(log.did + suffix, null))
                .isInstanceOf(DidResolutionException.class);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"basic-create-python", "basic-update-ts", "key-rotation-java-eecc", "pre-rotation-consume-rust"})
    void validatesIndependentImplementationHistories(String name) throws Exception {
        String log = resource(name + "/did.jsonl");
        String did = DidWebVhLog.JSON
                .readTree(log.lines().reduce((a, b) -> b).orElseThrow())
                .path("state")
                .path("id")
                .asText();
        assertThat(DidWebVhLog.validate(did, log, () -> resource(name + "/did-witness.json"))
                        .document()
                        .path("id")
                        .asText())
                .isEqualTo(did);
    }

    @ParameterizedTest
    @ValueSource(strings = {"deactivate-java-eecc", "negative-cross-did-witness-replay-ts", "witness-update-rust"})
    void rejectsIndependentNegativeFixtures(String name) throws Exception {
        String log = resource(name + "/did.jsonl");
        String did = DidWebVhLog.JSON
                .readTree(log.lines().findFirst().orElseThrow())
                .path("state")
                .path("id")
                .asText();
        assertThatThrownBy(() -> DidWebVhLog.validate(did, log, () -> resource(name + "/did-witness.json")))
                .isInstanceOf(DidResolutionException.class);
    }

    @Test
    void httpUsesKeycloakClientWithBoundedResponsesAndNoRedirects() throws Exception {
        var log = new WebVhTestLog(new WebVhTestLog.TestSigner().publicKey());
        KeycloakSession session = mock(KeycloakSession.class);
        HttpClientProvider provider = mock(HttpClientProvider.class);
        CloseableHttpClient client = mock(CloseableHttpClient.class);
        CloseableHttpResponse response = mock(CloseableHttpResponse.class);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(provider);
        when(provider.getHttpClient()).thenReturn(client);
        when(response.getStatusLine()).thenReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 200, "OK"));
        when(response.getEntity()).thenReturn(new ByteArrayEntity(log.jsonl().getBytes(StandardCharsets.UTF_8)));
        when(client.execute(any(HttpGet.class))).thenAnswer(call -> {
            HttpGet request = call.getArgument(0);
            assertThat(request.getURI().toString()).isEqualTo("https://issuer.example/.well-known/did.jsonl");
            assertThat(request.getConfig().isRedirectsEnabled()).isFalse();
            assertThat(request.getConfig().getSocketTimeout()).isEqualTo(10_000);
            return response;
        });
        assertThat(new DidWebVhResolver(session, 0).resolve(log.did, null)).hasSize(1);
        when(response.getEntity()).thenReturn(new ByteArrayEntity(new byte[DidWebVhResolver.MAX_RESPONSE_BYTES + 1]));
        assertThatThrownBy(() -> new DidWebVhResolver(session, 0).resolve(log.did, null))
                .isInstanceOf(DidResolutionException.class);
        when(response.getStatusLine()).thenReturn(new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 302, "Found"));
        assertThatThrownBy(() -> new DidWebVhResolver(session, 0).resolve(log.did, null))
                .isInstanceOf(DidResolutionException.class);
        verify(response, times(3)).close();
    }

    private static DidWebVhResolver resolver(Function<String, String> fetch) {
        return new DidWebVhResolver(fetch, 3600, Clock.systemUTC());
    }

    private static String resource(String path) {
        try (var input = DidWebVhResolverTest.class.getResourceAsStream("/did-webvh/" + path)) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
