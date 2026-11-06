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
package io.github.suengineering.keycloak.oid4vp.verification;

import com.authlete.cbor.CBORBoolean;
import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpJwk;
import io.github.suengineering.keycloak.oid4vp.util.Hpke;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ISO/IEC 18013-7 Annex C: mdoc presentation over the W3C Digital Credentials API with protocol
 * {@code org-iso-mdoc}, the protocol Safari and Apple Wallet use.
 *
 * <pre>
 * request data   = {"deviceRequest": b64u(CBOR DeviceRequest), "encryptionInfo": b64u(CBOR EncryptionInfo)}
 * EncryptionInfo = ["dcapi", {"nonce": bstr, "recipientPublicKey": COSE_Key}]
 * SessionTranscript = [null, null, ["dcapi", SHA-256(CBOR([encryptionInfo as sent, origin]))]]
 * response data  = {"response": b64u(CBOR ["dcapi", {"enc": bstr, "cipherText": bstr}])}
 * HPKE base mode, DHKEM(P-256)/HKDF-SHA256/AES-128-GCM, info = CBOR(SessionTranscript), aad empty;
 * the plaintext is a CBOR DeviceResponse.
 * </pre>
 *
 * <p>The request is built from the DCQL query, so it is only available when every credential query
 * is {@code mso_mdoc} with its own docType. With a P-256 reader key and certificate it is a version
 * 1.1 DeviceRequest signed with {@code readerAuthAll}, which Apple Wallet requires; otherwise an
 * unsigned version 1.0 request.
 */
public final class IsoMdocDcApi {

    public static final String PROTOCOL = "org-iso-mdoc";

    private static final String DCAPI = "dcapi";
    private static final int NONCE_BYTES = 16;
    private static final int COSE_ALG_ES256 = -7;
    private static final int COSE_HEADER_ALG = 1;
    private static final int COSE_HEADER_X5CHAIN = 33;
    private static final int MAX_RESPONSE_CHARS = 2 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper();

    private IsoMdocDcApi() {}

    /** One requested document: the DCQL credential query ID and what it asks for. */
    public record DocQuery(String credentialId, String docType, Map<String, List<String>> elements) {}

    /** The values the page passes to the browser and the secrets kept to read the answer. */
    public record PreparedRequest(String deviceRequest, String encryptionInfo, String recipientKeyJson) {}

    /** A signing key with its certificate chain, leaf first. */
    public record ReaderKey(PrivateKey privateKey, List<X509Certificate> certificateChain) {}

    /**
     * Maps a DCQL query to ISO document requests, or returns an empty list when it cannot be
     * expressed: a non-mdoc credential, a repeated docType, or a claim path that is not
     * {@code [namespace, element]}.
     */
    public static List<DocQuery> docQueries(String dcqlQuery) {
        try {
            JsonNode credentials = JSON.readTree(dcqlQuery).path("credentials");
            if (!credentials.isArray() || credentials.isEmpty()) return List.of();
            List<DocQuery> queries = new ArrayList<>();
            Set<String> docTypes = new HashSet<>();
            for (JsonNode credential : credentials) {
                String docType = credential.path("meta").path("doctype_value").asText("");
                if (!"mso_mdoc".equals(credential.path("format").asText())
                        || docType.isBlank()
                        || !docTypes.add(docType)) {
                    return List.of();
                }
                Map<String, List<String>> elements = new LinkedHashMap<>();
                for (JsonNode claim : credential.path("claims")) {
                    JsonNode path = claim.path("path");
                    if (!path.isArray()
                            || path.size() != 2
                            || !path.get(0).isTextual()
                            || !path.get(1).isTextual()) {
                        return List.of();
                    }
                    elements.computeIfAbsent(path.get(0).textValue(), ns -> new ArrayList<>())
                            .add(path.get(1).textValue());
                }
                if (elements.isEmpty()) return List.of();
                queries.add(new DocQuery(credential.path("id").asText(), docType, elements));
            }
            return queries;
        } catch (Exception e) {
            return List.of();
        }
    }

    /** Builds the request for {@code origin}; {@code readerKey} may be {@code null} for an unsigned request. */
    public static PreparedRequest prepare(String dcqlQuery, String origin, ReaderKey readerKey) {
        List<DocQuery> queries = docQueries(dcqlQuery);
        if (queries.isEmpty()) {
            throw new IllegalArgumentException("The DCQL query cannot be expressed as an ISO mdoc request");
        }
        try {
            Oid4vpJwk recipientKey = Oid4vpJwk.generate("P-256", "HPKE", "enc");
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            CBORItemList encryptionInfo = new CBORItemList(
                    new CBORString(DCAPI),
                    map(
                            pair("nonce", new CBORByteArray(nonce)),
                            pair("recipientPublicKey", coseKey(recipientKey.toPublicKey()))));
            String encryptionInfoB64 = b64(encryptionInfo.encode());
            CBORItemList transcript = sessionTranscript(encryptionInfoB64, origin);

            List<CBORTaggedItem> itemsRequests = new ArrayList<>();
            List<CBORItem> docRequests = new ArrayList<>();
            for (DocQuery query : queries) {
                CBORTaggedItem itemsRequest = tag24(itemsRequest(query));
                itemsRequests.add(itemsRequest);
                docRequests.add(map(pair("itemsRequest", itemsRequest)));
            }

            List<CBORPair> deviceRequest = new ArrayList<>();
            if (readerKey == null) {
                deviceRequest.add(pair("version", new CBORString("1.0")));
                deviceRequest.add(pair("docRequests", new CBORItemList(docRequests)));
            } else {
                // iOS 26 expects useCases in a 1.1 request.
                CBORTaggedItem deviceRequestInfo = tag24(map(pair("useCases", useCases(dcqlQuery, queries))));
                CBORItemList readerAuthenticationAll = new CBORItemList(
                        new CBORString("ReaderAuthenticationAll"),
                        transcript,
                        new CBORItemList(new ArrayList<CBORItem>(itemsRequests)),
                        deviceRequestInfo);
                deviceRequest.add(pair("version", new CBORString("1.1")));
                deviceRequest.add(pair("docRequests", new CBORItemList(docRequests)));
                deviceRequest.add(pair("deviceRequestInfo", deviceRequestInfo));
                deviceRequest.add(pair(
                        "readerAuthAll",
                        new CBORItemList(
                                sign(readerKey, tag24(readerAuthenticationAll).encode()))));
            }
            return new PreparedRequest(
                    b64(new CBORPairList(deviceRequest).encode()), encryptionInfoB64, recipientKey.toJson());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to build the ISO mdoc request", e);
        }
    }

    /** The Annex C SessionTranscript over the {@code encryptionInfo} string exactly as it was sent. */
    public static CBORItemList sessionTranscript(String encryptionInfoB64, String origin) {
        byte[] dcapiInfo = new CBORItemList(new CBORString(encryptionInfoB64), new CBORString(origin)).encode();
        CBORItemList handover = new CBORItemList(
                new CBORString(DCAPI), new CBORByteArray(MdocSessionTranscriptBuilder.sha256(dcapiInfo)));
        return new CBORItemList(CBORNull.INSTANCE, CBORNull.INSTANCE, handover);
    }

    /**
     * Decrypts the {@code response} the browser returned and splits the DeviceResponse into one
     * single-document DeviceResponse per credential query, keyed like an OpenID4VP {@code vp_token}.
     */
    public static Map<String, List<String>> openResponse(
            String responseB64, PreparedRequest request, String origin, List<DocQuery> queries) {
        if (responseB64 == null || responseB64.isBlank() || responseB64.length() > MAX_RESPONSE_CHARS) {
            throw new IllegalArgumentException("Missing or oversized org-iso-mdoc response");
        }
        try {
            CBORItem decoded = decode(Base64.getUrlDecoder().decode(responseB64.replace("=", "")));
            if (!(decoded instanceof CBORItemList envelope)
                    || envelope.getItems().size() != 2
                    || !DCAPI.equals(text(envelope.getItems().get(0)))
                    || !(envelope.getItems().get(1) instanceof CBORPairList parameters)) {
                throw new IllegalArgumentException("org-iso-mdoc response is not a dcapi EncryptedResponse");
            }
            byte[] enc = bytes(field(parameters, "enc"));
            byte[] cipherText = bytes(field(parameters, "cipherText"));
            Oid4vpJwk recipientKey = Oid4vpJwk.parse(request.recipientKeyJson());
            byte[] info = sessionTranscript(request.encryptionInfo(), origin).encode();
            byte[] plainText = Hpke.open(
                    recipientKey.toPrivateKey(), recipientKey.toPublicKey(), enc, info, new byte[0], cipherText);
            return splitDocuments(plainText, queries);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("org-iso-mdoc response could not be decrypted", e);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unreadable org-iso-mdoc response: " + e.getMessage(), e);
        }
    }

    static Map<String, List<String>> splitDocuments(byte[] deviceResponse, List<DocQuery> queries) throws Exception {
        if (!(decode(deviceResponse) instanceof CBORPairList root)) {
            throw new IllegalArgumentException("DeviceResponse is not a map");
        }
        CBORItem status = field(root, "status");
        if (!(status instanceof CBORInteger code) || code.getValue() != 0) {
            throw new IllegalArgumentException("Wallet returned DeviceResponse status " + status);
        }
        Map<String, String> idByDocType = new LinkedHashMap<>();
        queries.forEach(query -> idByDocType.put(query.docType(), query.credentialId()));
        Map<String, List<String>> presentations = new LinkedHashMap<>();
        CBORItem documents = field(root, "documents");
        if (documents instanceof CBORItemList list) {
            for (CBORItem document : list.getItems()) {
                String docType = document instanceof CBORPairList doc ? text(field(doc, "docType")) : null;
                String credentialId = idByDocType.get(docType);
                if (credentialId == null) {
                    throw new IllegalArgumentException("DeviceResponse contains an unrequested document: " + docType);
                }
                CBORPairList single = map(
                        pair("version", field(root, "version")),
                        pair("documents", new CBORItemList(document)),
                        pair("status", new CBORInteger(0)));
                presentations
                        .computeIfAbsent(credentialId, id -> new ArrayList<>())
                        .add(b64(single.encode()));
            }
        }
        return presentations;
    }

    /** DCQL credential sets become use cases; without them, one mandatory use case asks for every document. */
    private static CBORItemList useCases(String dcqlQuery, List<DocQuery> queries) throws GeneralSecurityException {
        Map<String, Integer> indexById = new LinkedHashMap<>();
        for (int i = 0; i < queries.size(); i++) indexById.put(queries.get(i).credentialId(), i);
        List<CBORItem> useCases = new ArrayList<>();
        try {
            JsonNode sets = JSON.readTree(dcqlQuery).path("credential_sets");
            for (JsonNode set : sets) {
                List<CBORItem> documentSets = new ArrayList<>();
                for (JsonNode option : set.path("options")) {
                    List<CBORItem> ids = new ArrayList<>();
                    for (JsonNode id : option) ids.add(new CBORInteger(indexById.get(id.asText())));
                    documentSets.add(new CBORItemList(ids));
                }
                useCases.add(map(
                        pair("mandatory", set.path("required").asBoolean(true) ? CBORBoolean.TRUE : CBORBoolean.FALSE),
                        pair("documentSets", new CBORItemList(documentSets))));
            }
        } catch (Exception e) {
            throw new GeneralSecurityException("Unreadable DCQL credential_sets", e);
        }
        if (useCases.isEmpty()) {
            List<CBORItem> all = new ArrayList<>();
            for (int i = 0; i < queries.size(); i++) all.add(new CBORInteger(i));
            useCases.add(map(
                    pair("mandatory", CBORBoolean.TRUE),
                    pair("documentSets", new CBORItemList(new CBORItemList(all)))));
        }
        return new CBORItemList(useCases);
    }

    private static CBORPairList itemsRequest(DocQuery query) {
        List<CBORPair> namespaces = new ArrayList<>();
        query.elements().forEach((namespace, elements) -> {
            List<CBORPair> intents = new ArrayList<>();
            elements.forEach(element -> intents.add(pair(element, CBORBoolean.FALSE)));
            namespaces.add(pair(namespace, new CBORPairList(intents)));
        });
        return map(pair("docType", new CBORString(query.docType())), pair("nameSpaces", new CBORPairList(namespaces)));
    }

    /** COSE_Sign1 with a detached payload, ES256 (alg -7, as ISO 18013-5 requires) and x5chain. */
    private static CBORItemList sign(ReaderKey readerKey, byte[] detachedPayload) throws GeneralSecurityException {
        if (!(readerKey.privateKey() instanceof ECPrivateKey ecKey)
                || ecKey.getParams().getCurve().getField().getFieldSize() != 256) {
            throw new GeneralSecurityException("ISO reader authentication needs a P-256 key");
        }
        byte[] protectedHeader = map(new CBORPair(new CBORInteger(COSE_HEADER_ALG), new CBORInteger(COSE_ALG_ES256)))
                .encode();
        byte[] sigStructure = new CBORItemList(
                        new CBORString("Signature1"),
                        new CBORByteArray(protectedHeader),
                        new CBORByteArray(new byte[0]),
                        new CBORByteArray(detachedPayload))
                .encode();
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(readerKey.privateKey());
        signer.update(sigStructure);
        byte[] signature = signer.sign();

        List<CBORItem> chain = new ArrayList<>();
        List<X509Certificate> certificates = readerKey.certificateChain();
        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate certificate = certificates.get(i);
            boolean selfSignedRoot =
                    i > 0 && certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
            if (!selfSignedRoot) chain.add(new CBORByteArray(certificate.getEncoded()));
        }
        CBORItem x5chain = chain.size() == 1 ? chain.get(0) : new CBORItemList(chain);
        return new CBORItemList(
                new CBORByteArray(protectedHeader),
                map(new CBORPair(new CBORInteger(COSE_HEADER_X5CHAIN), x5chain)),
                CBORNull.INSTANCE,
                new CBORByteArray(signature));
    }

    private static CBORPairList coseKey(ECPublicKey key) {
        return map(
                new CBORPair(new CBORInteger(1), new CBORInteger(2)),
                new CBORPair(new CBORInteger(-1), new CBORInteger(1)),
                new CBORPair(
                        new CBORInteger(-2),
                        new CBORByteArray(coordinate(key.getW().getAffineX()))),
                new CBORPair(
                        new CBORInteger(-3),
                        new CBORByteArray(coordinate(key.getW().getAffineY()))));
    }

    private static byte[] coordinate(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int length = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - length, out, 32 - length, length);
        return out;
    }

    private static CBORTaggedItem tag24(CBORItem item) {
        return new CBORTaggedItem(24, new CBORByteArray(item.encode()));
    }

    private static CBORPair pair(String key, CBORItem value) {
        return new CBORPair(new CBORString(key), value);
    }

    private static CBORPairList map(CBORPair... pairs) {
        return new CBORPairList(List.of(pairs));
    }

    private static CBORItem decode(byte[] bytes) throws Exception {
        io.github.suengineering.keycloak.oid4vp.util.CborLimits.check(bytes);
        return new CBORDecoder(bytes).next();
    }

    private static CBORItem field(CBORPairList map, String key) {
        for (CBORPair pair : map.getPairs()) {
            if (pair.getKey() instanceof CBORString name && key.equals(name.getValue())) return pair.getValue();
        }
        return null;
    }

    private static String text(CBORItem item) {
        return item instanceof CBORString string ? string.getValue() : null;
    }

    private static byte[] bytes(CBORItem item) {
        if (item instanceof CBORByteArray array) return array.getValue();
        throw new IllegalArgumentException("Expected a byte string");
    }

    static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
