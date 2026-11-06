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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import io.github.suengineering.keycloak.oid4vp.domain.MdocVerificationResult;
import io.github.suengineering.keycloak.oid4vp.domain.Oid4vpJwk;
import io.github.suengineering.keycloak.oid4vp.util.Hpke;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IsoMdocDcApiTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String ORIGIN = "https://login.example.com";
    private static final String MDL_QUERY = """
            {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
              "claims":[{"path":["org.iso.18013.5.1","given_name"]},{"path":["org.iso.18013.5.1","age_over_18"]}]}]}
            """;

    // walt.id ANNEXC-DETERMINISTIC-001 (waltid-identity, waltid-18013-7-verifier test resources).
    private static final String V1_ORIGIN = "https://verifier.example";
    private static final String V1_ENCRYPTION_INFO =
            "gmVkY2FwaaJlbm9uY2VQAAECAwQFBgcICQoLDA0OD3JyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFYILO0LJXwA8VAp7-rI9YIJvj1wfEQ122YdEjwxUFeYAFEIlgg0u68CgTFZk_nslWFmYhDMQQ6vdBNf2vwy3QHKI_80Js";
    private static final String V1_RESPONSE =
            "gmVkY2FwaaJjZW5jWEEEG5gvoNUFmbbhxRtSl075PExgPLGtxDb9Hxu_VnVe03aaHuJ-vW219YofqLJJGUHZKgrrjcEmoLYT0ur35BJCBGpjaXBoZXJUZXh0WCXUGzq3WpzY3INchUZw8cbzbz8bWJueKZ4PLW0LEvhDmmQPAKOa";
    private static final String V1_SK = "9baeb7b14495d7b69cbe751a98c7ee4ad36b41053da880fe00baa4bb5ce31372";
    private static final String V1_PK_X = "b3b42c95f003c540a7bfab23d60826f8f5c1f110d76d987448f0c5415e600144";
    private static final String V1_PK_Y = "d2eebc0a04c5664fe7b2558599884331043abdd04d7f6bf0cb7407288ffcd09b";

    @Test
    void sessionTranscript_matchesTheWaltIdVector() throws Exception {
        byte[] transcript =
                IsoMdocDcApi.sessionTranscript(V1_ENCRYPTION_INFO, V1_ORIGIN).encode();

        assertThat(HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(transcript)))
                .isEqualTo("564a34efc36b9b5a5ccafb6bf2e923cd96cc4a9c3712407f887d1e84d3bb58e4");
    }

    @Test
    void sessionTranscript_matchesTheEuAgeVerificationVector() {
        String encryptionInfo =
                "gmVkY2FwaaJlbm9uY2VQtJvGiCZ0egQII8fQgu960HJyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFYIMmliVBWgs8KKpAychO3py0Eqagows-CrraFX1rVOniXIlggIMvYr_x55AY4LKiWZLHBlQJmX1R9Y5BkUfnuSddAmyE";
        byte[] transcript = IsoMdocDcApi.sessionTranscript(encryptionInfo, "https://verifier.ageverification.dev")
                .encode();

        assertThat(HEX.formatHex(transcript))
                .isEqualTo("83f6f68265646361706958204a292708fcf38ad55a7969f1c97ead9decf7756b7e9d8cfee942fe9f31b8db0a");
    }

    @Test
    void openResponse_decryptsTheWaltIdVector() {
        String recipientKey = new Oid4vpJwk("P-256", b64(V1_PK_X), b64(V1_PK_Y), b64(V1_SK), null, null, null).toJson();
        IsoMdocDcApi.PreparedRequest request = new IsoMdocDcApi.PreparedRequest(null, V1_ENCRYPTION_INFO, recipientKey);

        // The vector's DeviceResponse is {version: "1.0", status: 0} with no documents.
        assertThat(IsoMdocDcApi.openResponse(V1_RESPONSE, request, V1_ORIGIN, List.of()))
                .isEmpty();
        assertThatThrownBy(() -> IsoMdocDcApi.openResponse(V1_RESPONSE, request, "https://other.example", List.of()))
                .hasMessageContaining("could not be decrypted");
    }

    @Test
    void prepare_unsignedRequestIsVersion10WithTheRequestedElements() throws Exception {
        IsoMdocDcApi.PreparedRequest request = IsoMdocDcApi.prepare(MDL_QUERY, ORIGIN, null);

        CBORPairList deviceRequest = (CBORPairList) decode(request.deviceRequest());
        assertThat(text(field(deviceRequest, "version"))).isEqualTo("1.0");
        assertThat(field(deviceRequest, "readerAuthAll")).isNull();
        CBORPairList docRequest = (CBORPairList)
                ((CBORItemList) field(deviceRequest, "docRequests")).getItems().get(0);
        CBORPairList itemsRequest = untag(field(docRequest, "itemsRequest"));
        assertThat(text(field(itemsRequest, "docType"))).isEqualTo("org.iso.18013.5.1.mDL");
        CBORPairList elements =
                (CBORPairList) field((CBORPairList) field(itemsRequest, "nameSpaces"), "org.iso.18013.5.1");
        assertThat(elements.getPairs())
                .extracting(pair -> text(pair.getKey()))
                .containsExactly("given_name", "age_over_18");

        CBORItemList encryptionInfo = (CBORItemList) decode(request.encryptionInfo());
        assertThat(text(encryptionInfo.getItems().get(0))).isEqualTo("dcapi");
        CBORPairList parameters = (CBORPairList) encryptionInfo.getItems().get(1);
        assertThat(((CBORByteArray) field(parameters, "nonce")).getValue()).hasSize(16);
        CBORPairList coseKey = (CBORPairList) field(parameters, "recipientPublicKey");
        assertThat(coseKey.getPairs()).hasSize(4);
        assertThat(request.encryptionInfo()).doesNotContain("=");
    }

    @Test
    void prepare_signedRequestIsVersion11WithAVerifiableReaderAuthAll() throws Exception {
        KeyPair readerKeys = p256();
        X509Certificate readerCert = MdocDeviceResponseTestHelper.generateSelfSignedCert(readerKeys);

        IsoMdocDcApi.PreparedRequest request = IsoMdocDcApi.prepare(
                MDL_QUERY, ORIGIN, new IsoMdocDcApi.ReaderKey(readerKeys.getPrivate(), List.of(readerCert)));

        CBORPairList deviceRequest = (CBORPairList) decode(request.deviceRequest());
        assertThat(text(field(deviceRequest, "version"))).isEqualTo("1.1");
        CBORTaggedItem deviceRequestInfo = (CBORTaggedItem) field(deviceRequest, "deviceRequestInfo");
        assertThat(field(untag(deviceRequestInfo), "useCases")).isInstanceOf(CBORItemList.class);

        CBORItemList readerAuth = (CBORItemList) ((CBORItemList) field(deviceRequest, "readerAuthAll"))
                .getItems()
                .get(0);
        byte[] protectedHeader = ((CBORByteArray) readerAuth.getItems().get(0)).getValue();
        assertThat(HEX.formatHex(protectedHeader)).isEqualTo("a10126"); // {1: -7}
        CBORPairList unprotectedHeader = (CBORPairList) readerAuth.getItems().get(1);
        assertThat(((CBORByteArray) unprotectedHeader.getPairs().get(0).getValue()).getValue())
                .isEqualTo(readerCert.getEncoded());

        CBORItem itemsRequest = field(
                (CBORPairList) ((CBORItemList) field(deviceRequest, "docRequests"))
                        .getItems()
                        .get(0),
                "itemsRequest");
        CBORItemList readerAuthenticationAll = new CBORItemList(
                new CBORString("ReaderAuthenticationAll"),
                IsoMdocDcApi.sessionTranscript(request.encryptionInfo(), ORIGIN),
                new CBORItemList(itemsRequest),
                deviceRequestInfo);
        byte[] detached = new CBORTaggedItem(24, new CBORByteArray(readerAuthenticationAll.encode())).encode();
        byte[] sigStructure = new CBORItemList(
                        new CBORString("Signature1"),
                        new CBORByteArray(protectedHeader),
                        new CBORByteArray(new byte[0]),
                        new CBORByteArray(detached))
                .encode();
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(readerCert.getPublicKey());
        verifier.update(sigStructure);
        assertThat(verifier.verify(((CBORByteArray) readerAuth.getItems().get(3)).getValue()))
                .isTrue();
    }

    @Test
    void docQueries_onlyCoversQueriesExpressibleAsIsoRequests() {
        assertThat(IsoMdocDcApi.docQueries(MDL_QUERY)).singleElement().satisfies(query -> {
            assertThat(query.credentialId()).isEqualTo("mdl");
            assertThat(query.elements()).containsEntry("org.iso.18013.5.1", List.of("given_name", "age_over_18"));
        });
        assertThat(
                        IsoMdocDcApi.docQueries(
                                "{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\",\"claims\":[{\"path\":[\"x\"]}]}]}"))
                .isEmpty();
        assertThat(IsoMdocDcApi.docQueries(MDL_QUERY.replace(
                        "]}]}",
                        "]},"
                                + "{\"id\":\"again\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"org.iso.18013.5.1.mDL\"},"
                                + "\"claims\":[{\"path\":[\"org.iso.18013.5.1\",\"x\"]}]}]}")))
                .as("a repeated docType cannot be matched back to its query")
                .isEmpty();
    }

    @Test
    void roundTrip_walletResponseVerifiesOnlyForTheRequestingOrigin() throws Exception {
        IsoMdocDcApi.PreparedRequest request = IsoMdocDcApi.prepare(MDL_QUERY, ORIGIN, null);
        MdocDeviceResponseTestHelper wallet = new MdocDeviceResponseTestHelper();
        CBORItemList transcript = IsoMdocDcApi.sessionTranscript(request.encryptionInfo(), ORIGIN);
        String encryptedResponse =
                encryptForVerifier(request, transcript, Base64.getUrlDecoder().decode(wallet.build(transcript)));

        Map<String, List<String>> presentations =
                IsoMdocDcApi.openResponse(encryptedResponse, request, ORIGIN, IsoMdocDcApi.docQueries(MDL_QUERY));

        assertThat(presentations).containsOnlyKeys("mdl");
        String document = presentations.get("mdl").get(0);
        MdocVerificationResult result = new MdocVerifier()
                .verifyIsoDcApi(document, List.of(wallet.issuerCert), request.encryptionInfo(), ORIGIN);
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
        assertThatThrownBy(() -> new MdocVerifier()
                        .verifyIsoDcApi(
                                document, List.of(wallet.issuerCert), request.encryptionInfo(), "https://evil.example"))
                .hasMessageContaining("deviceAuth signature invalid");
    }

    @Test
    void openResponse_rejectsDocumentsNobodyAskedFor() throws Exception {
        IsoMdocDcApi.PreparedRequest request = IsoMdocDcApi.prepare(MDL_QUERY, ORIGIN, null);
        CBORItemList transcript = IsoMdocDcApi.sessionTranscript(request.encryptionInfo(), ORIGIN);
        String otherDoc =
                new MdocDeviceResponseTestHelper().docType("org.example.other").build(transcript);
        String encryptedResponse =
                encryptForVerifier(request, transcript, Base64.getUrlDecoder().decode(otherDoc));

        assertThatThrownBy(() -> IsoMdocDcApi.openResponse(
                        encryptedResponse, request, ORIGIN, IsoMdocDcApi.docQueries(MDL_QUERY)))
                .hasMessageContaining("unrequested document");
    }

    @Test
    void openResponse_rejectsAnErrorStatus() throws Exception {
        IsoMdocDcApi.PreparedRequest request = IsoMdocDcApi.prepare(MDL_QUERY, ORIGIN, null);
        CBORItemList transcript = IsoMdocDcApi.sessionTranscript(request.encryptionInfo(), ORIGIN);
        byte[] failed = new CBORPairList(List.of(
                        new CBORPair(new CBORString("version"), new CBORString("1.0")),
                        new CBORPair(new CBORString("status"), new CBORInteger(20))))
                .encode();

        assertThatThrownBy(() -> IsoMdocDcApi.openResponse(
                        encryptForVerifier(request, transcript, failed),
                        request,
                        ORIGIN,
                        IsoMdocDcApi.docQueries(MDL_QUERY)))
                .hasMessageContaining("status 20");
    }

    /** What the wallet does: HPKE-seal the DeviceResponse to the recipient key, bound to the transcript. */
    private static String encryptForVerifier(
            IsoMdocDcApi.PreparedRequest request, CBORItemList transcript, byte[] deviceResponse) throws Exception {
        CBORPairList coseKey = (CBORPairList) field(
                (CBORPairList) ((CBORItemList) decode(request.encryptionInfo()))
                        .getItems()
                        .get(1),
                "recipientPublicKey");
        byte[] x = null;
        byte[] y = null;
        for (CBORPair pair : coseKey.getPairs()) {
            int label = ((Number) ((CBORItem) pair.getKey()).parse()).intValue();
            if (label == -2) x = ((CBORByteArray) pair.getValue()).getValue();
            if (label == -3) y = ((CBORByteArray) pair.getValue()).getValue();
        }
        byte[] point = new byte[65];
        point[0] = 0x04;
        System.arraycopy(x, 0, point, 1, 32);
        System.arraycopy(y, 0, point, 33, 32);
        Hpke.Sealed sealed = Hpke.seal(Hpke.decodePoint(point), transcript.encode(), new byte[0], deviceResponse);
        byte[] envelope = new CBORItemList(
                        new CBORString("dcapi"),
                        new CBORPairList(List.of(
                                new CBORPair(new CBORString("enc"), new CBORByteArray(sealed.enc())),
                                new CBORPair(new CBORString("cipherText"), new CBORByteArray(sealed.cipherText())))))
                .encode();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(envelope);
    }

    private static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(Hpke.p256Parameters());
        return generator.generateKeyPair();
    }

    private static CBORItem decode(String b64) throws Exception {
        return new CBORDecoder(Base64.getUrlDecoder().decode(b64)).next();
    }

    private static CBORPairList untag(CBORItem tagged) throws Exception {
        byte[] content = ((CBORByteArray) ((CBORTaggedItem) tagged).getTagContent()).getValue();
        return (CBORPairList) new CBORDecoder(content).next();
    }

    private static CBORItem field(CBORPairList map, String key) {
        for (CBORPair pair : map.getPairs()) {
            if (pair.getKey() instanceof CBORString name && key.equals(name.getValue())) return pair.getValue();
        }
        return null;
    }

    private static String text(Object item) {
        return item instanceof CBORString string ? string.getValue() : null;
    }

    private static String b64(String hex) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(HEX.parseHex(hex));
    }
}
