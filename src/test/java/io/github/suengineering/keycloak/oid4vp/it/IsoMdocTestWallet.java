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
package io.github.suengineering.keycloak.oid4vp.it;

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
import io.github.suengineering.keycloak.oid4vp.util.Hpke;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Answers an ISO/IEC 18013-7 Annex C ({@code org-iso-mdoc}) request the way a phone wallet would,
 * using a real issuer-signed mdoc from the eudi-dev wallet and the holder key that mdoc is bound to.
 * It is written from the Annex C structures, independently of the verifier code it tests.
 */
final class IsoMdocTestWallet {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The answer for {@code navigator.credentials.get()}, and whether the request carried a valid readerAuthAll. */
    record Answer(String credentialJson, boolean readerAuthVerified) {}

    private IsoMdocTestWallet() {}

    static Answer answer(String digitalRequestJson, String origin, String issuerSignedB64, PrivateKey holderKey)
            throws Exception {
        JsonNode isoRequest = null;
        for (JsonNode request :
                JSON.readTree(digitalRequestJson).path("digital").path("requests")) {
            if ("org-iso-mdoc".equals(request.path("protocol").asText())) isoRequest = request.path("data");
        }
        if (isoRequest == null) throw new IllegalStateException("No org-iso-mdoc request offered");
        String encryptionInfo = isoRequest.path("encryptionInfo").asText();
        CBORPairList deviceRequest =
                (CBORPairList) decode(b64(isoRequest.path("deviceRequest").asText()));

        // SessionTranscript = [null, null, ["dcapi", SHA-256(CBOR([encryptionInfo, origin]))]]
        byte[] dcapiInfo = new CBORItemList(new CBORString(encryptionInfo), new CBORString(origin)).encode();
        CBORItemList transcript = new CBORItemList(
                CBORNull.INSTANCE,
                CBORNull.INSTANCE,
                new CBORItemList(
                        new CBORString("dcapi"),
                        new CBORByteArray(MessageDigest.getInstance("SHA-256").digest(dcapiInfo))));

        CBORPairList docRequest = (CBORPairList)
                ((CBORItemList) get(deviceRequest, "docRequests")).getItems().get(0);
        CBORItem itemsRequestBytes = get(docRequest, "itemsRequest");
        CBORPairList itemsRequest = (CBORPairList) untag(itemsRequestBytes);
        String docType = ((CBORString) get(itemsRequest, "docType")).getValue();
        Set<String> requested = new HashSet<>();
        for (CBORPair namespace : ((CBORPairList) get(itemsRequest, "nameSpaces")).getPairs()) {
            for (CBORPair element : ((CBORPairList) namespace.getValue()).getPairs()) {
                requested.add(((CBORString) element.getKey()).getValue());
            }
        }
        boolean readerAuthVerified = verifyReaderAuthAll(deviceRequest, transcript, itemsRequestBytes);

        CBORPairList issuerSigned = (CBORPairList) decode(b64(issuerSignedB64));
        CBORPairList disclosed = disclose((CBORPairList) get(issuerSigned, "nameSpaces"), requested);
        CBORTaggedItem deviceNameSpaces =
                new CBORTaggedItem(24, new CBORByteArray(new CBORPairList(List.of()).encode()));
        CBORItemList deviceAuthentication = new CBORItemList(
                new CBORString("DeviceAuthentication"), transcript, new CBORString(docType), deviceNameSpaces);
        byte[] deviceAuthenticationBytes =
                new CBORTaggedItem(24, new CBORByteArray(deviceAuthentication.encode())).encode();
        CBORItemList deviceSignature = coseSign1Detached(holderKey, deviceAuthenticationBytes);

        CBORPairList document = map(
                pair("docType", new CBORString(docType)),
                pair(
                        "issuerSigned",
                        map(pair("nameSpaces", disclosed), pair("issuerAuth", get(issuerSigned, "issuerAuth")))),
                pair(
                        "deviceSigned",
                        map(
                                pair("nameSpaces", deviceNameSpaces),
                                pair("deviceAuth", map(pair("deviceSignature", deviceSignature))))));
        byte[] deviceResponse = map(
                        pair("version", new CBORString("1.0")),
                        pair("documents", new CBORItemList(document)),
                        pair("status", new CBORInteger(0)))
                .encode();

        CBORPairList encryptionParameters = (CBORPairList)
                ((CBORItemList) decode(b64(encryptionInfo))).getItems().get(1);
        Hpke.Sealed sealed = Hpke.seal(
                Hpke.decodePoint(uncompressedPoint((CBORPairList) get(encryptionParameters, "recipientPublicKey"))),
                transcript.encode(),
                new byte[0],
                deviceResponse);
        byte[] encryptedResponse = new CBORItemList(
                        new CBORString("dcapi"),
                        map(
                                pair("enc", new CBORByteArray(sealed.enc())),
                                pair("cipherText", new CBORByteArray(sealed.cipherText()))))
                .encode();
        String credential = JSON.writeValueAsString(Map.of(
                "protocol",
                "org-iso-mdoc",
                "data",
                Map.of("response", Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedResponse))));
        return new Answer(credential, readerAuthVerified);
    }

    private static boolean verifyReaderAuthAll(
            CBORPairList deviceRequest, CBORItemList transcript, CBORItem itemsRequestBytes) throws Exception {
        CBORItem readerAuthAll = get(deviceRequest, "readerAuthAll");
        if (!(readerAuthAll instanceof CBORItemList signatures)
                || signatures.getItems().isEmpty()) return false;
        CBORItemList sign1 = (CBORItemList) signatures.getItems().get(0);
        CBORItem deviceRequestInfo = get(deviceRequest, "deviceRequestInfo");
        CBORItemList readerAuthentication = new CBORItemList(
                new CBORString("ReaderAuthenticationAll"),
                transcript,
                new CBORItemList(itemsRequestBytes),
                deviceRequestInfo != null ? deviceRequestInfo : CBORNull.INSTANCE);
        byte[] payload = new CBORTaggedItem(24, new CBORByteArray(readerAuthentication.encode())).encode();
        byte[] protectedHeader = ((CBORByteArray) sign1.getItems().get(0)).getValue();
        CBORItem x5chain =
                ((CBORPairList) sign1.getItems().get(1)).getPairs().get(0).getValue();
        byte[] leaf = x5chain instanceof CBORItemList chain
                ? ((CBORByteArray) chain.getItems().get(0)).getValue()
                : ((CBORByteArray) x5chain).getValue();
        X509Certificate certificate = (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(leaf));
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(sigStructure(protectedHeader, payload));
        return verifier.verify(((CBORByteArray) sign1.getItems().get(3)).getValue());
    }

    private static CBORPairList disclose(CBORPairList nameSpaces, Set<String> requested) throws Exception {
        List<CBORPair> out = new ArrayList<>();
        for (CBORPair namespace : nameSpaces.getPairs()) {
            List<CBORItem> items = new ArrayList<>();
            for (CBORItem item : ((CBORItemList) namespace.getValue()).getItems()) {
                CBORPairList signedItem = (CBORPairList) untag(item);
                if (requested.contains(((CBORString) get(signedItem, "elementIdentifier")).getValue())) items.add(item);
            }
            if (!items.isEmpty()) out.add(new CBORPair(namespace.getKey(), new CBORItemList(items)));
        }
        return new CBORPairList(out);
    }

    private static CBORItemList coseSign1Detached(PrivateKey key, byte[] payload) throws Exception {
        byte[] protectedHeader =
                new CBORPairList(List.of(new CBORPair(new CBORInteger(1), new CBORInteger(-7)))).encode();
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(key);
        signer.update(sigStructure(protectedHeader, payload));
        return new CBORItemList(
                new CBORByteArray(protectedHeader),
                new CBORPairList(List.of()),
                CBORNull.INSTANCE,
                new CBORByteArray(signer.sign()));
    }

    private static byte[] sigStructure(byte[] protectedHeader, byte[] payload) {
        return new CBORItemList(
                        new CBORString("Signature1"),
                        new CBORByteArray(protectedHeader),
                        new CBORByteArray(new byte[0]),
                        new CBORByteArray(payload))
                .encode();
    }

    private static byte[] uncompressedPoint(CBORPairList coseKey) {
        byte[] point = new byte[65];
        point[0] = 0x04;
        for (CBORPair pair : coseKey.getPairs()) {
            int label = ((Number) pair.getKey().parse()).intValue();
            if (label == -2) System.arraycopy(((CBORByteArray) pair.getValue()).getValue(), 0, point, 1, 32);
            if (label == -3) System.arraycopy(((CBORByteArray) pair.getValue()).getValue(), 0, point, 33, 32);
        }
        return point;
    }

    private static CBORItem untag(CBORItem tagged) throws Exception {
        return decode(((CBORByteArray) ((CBORTaggedItem) tagged).getTagContent()).getValue());
    }

    private static CBORItem get(CBORPairList map, String key) {
        for (CBORPair pair : map.getPairs()) {
            if (pair.getKey() instanceof CBORString name && key.equals(name.getValue())) return pair.getValue();
        }
        return null;
    }

    private static CBORPair pair(String key, CBORItem value) {
        return new CBORPair(new CBORString(key), value);
    }

    private static CBORPairList map(CBORPair... pairs) {
        return new CBORPairList(List.of(pairs));
    }

    private static CBORItem decode(byte[] bytes) throws Exception {
        return new CBORDecoder(bytes).next();
    }

    private static byte[] b64(String value) {
        return Base64.getUrlDecoder().decode(value.replace("=", ""));
    }
}
