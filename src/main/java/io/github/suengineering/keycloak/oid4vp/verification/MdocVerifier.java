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

import com.authlete.cbor.CBORBoolean;
import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORDouble;
import com.authlete.cbor.CBORFloat;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORLong;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEKey;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import io.github.suengineering.keycloak.oid4vp.domain.MdocCertificateProfile;
import io.github.suengineering.keycloak.oid4vp.domain.MdocVerificationResult;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.utils.StringUtil;

/**
 * Verifies mDoc (ISO 18013-5) credentials presented in a VP token.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdocVerifier {

    private static final Logger LOG = Logger.getLogger(MdocVerifier.class);

    private final MdocCertificateProfile certificateProfile;
    private CertificateRevocationChecker revocationChecker = CertificateRevocationChecker.DISABLED;

    /** Checks document signer chains for revocation (CRL/OCSP) with {@code checker}. */
    public MdocVerifier withRevocationChecker(CertificateRevocationChecker checker) {
        this.revocationChecker = checker != null ? checker : CertificateRevocationChecker.DISABLED;
        return this;
    }

    public MdocVerifier() {
        this(MdocCertificateProfile.NONE);
    }

    public MdocVerifier(MdocCertificateProfile certificateProfile) {
        this.certificateProfile = certificateProfile != null ? certificateProfile : MdocCertificateProfile.NONE;
    }

    /**
     * The docType in the MobileSecurityObject, read without verifying anything. Used to pick the trust
     * anchors that may issue that docType; the signature checked afterwards binds the value.
     */
    public String signedDocType(String deviceResponseToken) {
        try {
            CBORPairList mso = parseMso(parseDocument(decodeBase64(deviceResponseToken)));
            return mso != null ? str(mso, "docType") : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static final int CBOR_TAG_DATE = 1004;

    public boolean isMdoc(String token) {
        if (StringUtil.isBlank(token)) return false;
        try {
            CBORItem root = decodeCbor(decodeBase64(token));
            if (!(root instanceof CBORPairList map)) return false;
            return val(map, "documents") != null || val(map, "nameSpaces") != null;
        } catch (Exception e) {
            return false;
        }
    }

    /** Issuer signature verification only (no device auth, digest, or validity checks). */
    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken, List<X509Certificate> trustedCertificates) {
        return verifyWithTrustedCerts(deviceResponseToken, trustedCertificates, null, null, null, null, null);
    }

    /**
     * Full verification: issuer signature, device authentication, value digests, MSO validity.
     * OID4VP 1.0 transcript is tried first; ISO 18013-7 as fallback when mdocGeneratedNonce is present.
     */
    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken,
            List<X509Certificate> trustedCertificates,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce,
            byte[] jwkThumbprint) {
        boolean anySessionContext = clientId != null || nonce != null || responseUri != null;
        boolean completeSessionContext = clientId != null && nonce != null && responseUri != null;
        if (anySessionContext && !completeSessionContext) {
            throw new IllegalStateException(
                    "mDoc presentation requires device authentication and complete session context");
        }
        List<CBORItemList> transcripts = null;
        if (completeSessionContext) {
            transcripts = new ArrayList<>();
            transcripts.add(MdocSessionTranscriptBuilder.buildOid4vp(clientId, nonce, responseUri, jwkThumbprint));
            if (mdocGeneratedNonce != null && !mdocGeneratedNonce.isBlank()) {
                transcripts.add(
                        MdocSessionTranscriptBuilder.buildIso18013_7(clientId, nonce, responseUri, mdocGeneratedNonce));
            }
        }
        return verify(deviceResponseToken, trustedCertificates, transcripts);
    }

    /**
     * Full verification of a presentation returned through the Digital Credentials API, with device
     * authentication bound to the {@code OpenID4VPDCAPIHandover} transcript (OID4VP 1.0 B.2.6.2).
     *
     * @param origin the browser origin the request was made from, without the {@code origin:} prefix
     * @param jwkThumbprint the verifier encryption key thumbprint for {@code dc_api.jwt}, else {@code null}
     */
    public MdocVerificationResult verifyDcApi(
            String deviceResponseToken,
            List<X509Certificate> trustedCertificates,
            String origin,
            String nonce,
            byte[] jwkThumbprint) {
        if (StringUtil.isBlank(origin) || StringUtil.isBlank(nonce)) {
            throw new IllegalStateException(
                    "mDoc presentation requires device authentication and complete session context");
        }
        return verify(
                deviceResponseToken,
                trustedCertificates,
                List.of(MdocSessionTranscriptBuilder.buildDcApi(origin, nonce, jwkThumbprint)));
    }

    /**
     * Full verification of a document from an ISO/IEC 18013-7 Annex C ({@code org-iso-mdoc})
     * response, with device authentication bound to the {@code dcapi} SessionTranscript.
     *
     * @param encryptionInfo the {@code encryptionInfo} string exactly as it was sent to the browser
     */
    public MdocVerificationResult verifyIsoDcApi(
            String deviceResponseToken,
            List<X509Certificate> trustedCertificates,
            String encryptionInfo,
            String origin) {
        if (StringUtil.isBlank(encryptionInfo) || StringUtil.isBlank(origin)) {
            throw new IllegalStateException(
                    "mDoc presentation requires device authentication and complete session context");
        }
        return verify(
                deviceResponseToken,
                trustedCertificates,
                List.of(IsoMdocDcApi.sessionTranscript(encryptionInfo, origin)));
    }

    /**
     * Verifies the document. With {@code transcripts == null} only issuer-side checks run; otherwise
     * device authentication is required and must verify against one of the candidate transcripts.
     */
    private MdocVerificationResult verify(
            String deviceResponseToken, List<X509Certificate> trustedCertificates, List<CBORItemList> transcripts) {
        try {
            CBORPairList document = parseDocument(decodeBase64(deviceResponseToken));
            CBORPairList mso = parseMso(document);

            if (mso == null) {
                throw new IllegalStateException("Missing or unreadable MobileSecurityObject");
            }
            String docType = str(mso, "docType");
            if (StringUtil.isBlank(docType)) {
                throw new IllegalStateException("Signed MSO has no docType");
            }
            String documentDocType = str(document, "docType");
            if (documentDocType != null && !docType.equals(documentDocType)) {
                throw new IllegalStateException("Document docType does not match signed MSO");
            }
            if (transcripts != null && val(document, "deviceSigned") == null) {
                throw new IllegalStateException(
                        "mDoc presentation requires device authentication and complete session context");
            }
            Map<String, Object> claims = extractClaims(document, mso);
            verifyIssuerSignature(document, mso, trustedCertificates);

            validateValidity(mso);
            verifyDigests(mso, document);
            if (transcripts != null) {
                verifyDeviceAuth(document, mso, docType, transcripts);
            }

            return new MdocVerificationResult(claims, docType, msoStatus(mso));
        } catch (Exception e) {
            throw wrapIfNeeded(e, "mDoc verification failed: ");
        }
    }

    private CBORPairList parseDocument(byte[] bytes) {
        CBORItem root = decodeCbor(bytes);
        if (!(root instanceof CBORPairList rootMap)) throw new IllegalStateException("Unknown mDoc structure");

        CBORItem docs = val(rootMap, "documents");
        if (docs instanceof CBORItemList docsList) {
            if (docsList.getItems() == null || docsList.getItems().isEmpty()) {
                throw new IllegalStateException("Empty documents array");
            }
            if (docsList.getItems().size() != 1) {
                throw new IllegalStateException("Each mDoc presentation must contain exactly one document");
            }
            if (docsList.getItems().get(0) instanceof CBORPairList doc) return doc;
            throw new IllegalStateException("Invalid document entry");
        }
        if (val(rootMap, "nameSpaces") != null) return rootMap;
        throw new IllegalStateException("Unknown mDoc structure");
    }

    private Map<String, Object> extractClaims(CBORPairList document, CBORPairList mso) {
        Map<String, Object> claims = new LinkedHashMap<>();

        // Claims come only from issuerSigned.nameSpaces, the elements verifyDigests checks against the MSO.
        CBORItem issuerSignedNameSpaces = val(map(document, "issuerSigned"), "nameSpaces");
        if (issuerSignedNameSpaces == null) return claims;
        if (!(issuerSignedNameSpaces instanceof CBORPairList nameSpaces)) {
            throw new IllegalStateException("issuerSigned.nameSpaces is not a map");
        }

        for (var nsPair : nameSpaces.getPairs()) {
            String namespace = stringValue(nsPair.getKey());
            if (namespace == null || !(nsPair.getValue() instanceof CBORItemList elementsList)) {
                throw new IllegalStateException("Malformed issuer-signed namespace");
            }
            addNamespaceClaims(claims, namespace, elementsList);
        }

        if (mso != null) {
            CBORItem status = val(mso, "status");
            if (status != null) claims.put("status", cborToJava(status));
        }
        return claims;
    }

    private void addNamespaceClaims(Map<String, Object> claims, String namespace, CBORItemList elementsList) {
        for (CBORItem element : elementsList.getItems()) {
            // ISO 18013-5 IssuerSignedItemBytes are tag 24; only that form is digest-checked as sent.
            if (!(element instanceof CBORTaggedItem tagged)
                    || tagged.getTagNumber().intValue() != 24) {
                throw new IllegalStateException("Issuer-signed item is not tag-24 encoded");
            }
            CBORPairList item = unwrapTag24(element);
            String elementId = item != null ? str(item, "elementIdentifier") : null;
            if (elementId == null) {
                throw new IllegalStateException("Issuer-signed item has no elementIdentifier");
            }
            claims.put(namespace + "/" + elementId, cborToJava(val(item, "elementValue")));
        }
    }

    /**
     * CBOR tag 24 means "encoded CBOR data item": the tag content is a byte string whose bytes
     * contain another CBOR structure. mdoc issuer-signed items commonly use this wrapper, so we
     * decode the inner bytes before reading fields like {@code elementIdentifier} or
     * {@code digestID}.
     */
    private CBORPairList unwrapTag24(CBORItem element) {
        if (element instanceof CBORTaggedItem tagged && tagged.getTagNumber().intValue() == 24) {
            CBORItem content = tagged.getTagContent();
            if (content instanceof CBORByteArray bstr) return asMap(decodeCbor(bstr.getValue()));
        }
        if (element instanceof CBORPairList m) return m;
        if (element instanceof CBORByteArray bstr) return asMap(decodeCbor(bstr.getValue()));
        return null;
    }

    private CBORPairList parseMso(CBORPairList document) {
        CBORItem issuerAuth = val(map(document, "issuerSigned"), "issuerAuth");
        if (issuerAuth == null) return null;

        CBORItem payload = buildCoseSign1(issuerAuth).getPayload();
        if (payload == null) return null;

        byte[] bytes = payload instanceof CBORByteArray bstr ? bstr.getValue() : payload.encode();
        CBORItem decoded = decodeCbor(bytes);

        if (decoded instanceof CBORTaggedItem tagged
                && tagged.getTagNumber().intValue() == 24
                && tagged.getTagContent() instanceof CBORByteArray bstr) {
            return asMap(decodeCbor(bstr.getValue()));
        }
        return asMap(decoded);
    }

    private void verifyIssuerSignature(
            CBORPairList document, CBORPairList mso, List<X509Certificate> trustedCertificates) {
        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            throw new IllegalStateException("No trusted keys available for mDoc signature verification");
        }

        CBORItem issuerAuth = val(map(document, "issuerSigned"), "issuerAuth");
        if (issuerAuth == null) throw new IllegalStateException("No issuerAuth found");

        try {
            COSESign1 sign1 = buildCoseSign1(issuerAuth);

            // ISO/IEC 18013-5 9.1.2.4: issuerAuth carries the document signer certificate in x5chain.
            // The chain must validate against the trust anchors; there is no fallback to trying
            // trusted keys directly, which would ignore the chain's validity and CA constraints.
            List<X509Certificate> x5chain = extractX5Chain(sign1);
            if (x5chain == null || x5chain.isEmpty()) {
                throw new IllegalStateException("issuerAuth has no x5chain");
            }
            X5cChainValidator.AnchoredChain anchored = X5cChainValidator.anchorChain(x5chain, trustedCertificates);
            revocationChecker.check(anchored);
            PublicKey leafKey = anchored.leafKey();
            if (certificateProfile == MdocCertificateProfile.ISO_18013_5) {
                Iso18013CertificateProfile.check(
                        x5chain, trustedCertificates, parseInstant(val(map(mso, "validityInfo"), "signed")));
            }
            if (!new COSEVerifier(leafKey).verify(sign1)) {
                throw new IllegalStateException("issuerAuth signature does not verify with the document signer key");
            }
        } catch (Exception e) {
            throw wrapIfNeeded(e, "Issuer signature verification failed: ");
        }
    }

    private List<X509Certificate> extractX5Chain(COSESign1 sign1) {
        try {
            if (sign1.getUnprotectedHeader() != null) {
                var chain = sign1.getUnprotectedHeader().getX5Chain();
                if (chain != null && !chain.isEmpty()) return chain;
            }
            if (sign1.getProtectedHeader() != null) {
                var chain = sign1.getProtectedHeader().getX5Chain();
                if (chain != null && !chain.isEmpty()) return chain;
            }
        } catch (Exception e) {
            LOG.debugf("Failed to extract x5chain: %s", e.getMessage());
        }
        return null;
    }

    private void verifyDeviceAuth(
            CBORPairList document, CBORPairList mso, String docType, List<CBORItemList> transcripts) {

        COSESign1 deviceSign1 = extractDeviceSignature(document);
        PublicKey deviceKey = extractDeviceKey(mso);
        CBORItem deviceNameSpaces = val(map(document, "deviceSigned"), "nameSpaces");
        if (deviceNameSpaces == null) deviceNameSpaces = new CBORPairList(List.of());

        // Candidates are ordered by preference: the OID4VP 1.0 transcript first, then any fallback.
        for (CBORItemList transcript : transcripts) {
            if (tryVerifyDevice(deviceSign1, deviceKey, transcript, docType, deviceNameSpaces)) {
                return;
            }
        }

        throw new IllegalStateException("deviceAuth signature invalid");
    }

    private COSESign1 extractDeviceSignature(CBORPairList document) {
        CBORPairList deviceSigned = map(document, "deviceSigned");
        if (deviceSigned == null) throw new IllegalStateException("Missing deviceSigned");

        CBORItem deviceAuth = val(deviceSigned, "deviceAuth");
        if (deviceAuth instanceof CBORPairList m) deviceAuth = val(m, "deviceSignature");
        if (deviceAuth == null) throw new IllegalStateException("Missing deviceSignature");

        return buildCoseSign1(deviceAuth);
    }

    private PublicKey extractDeviceKey(CBORPairList mso) {
        CBORItem deviceKey = val(map(mso, "deviceKeyInfo"), "deviceKey");
        if (deviceKey == null) throw new IllegalStateException("Missing deviceKeyInfo in MSO");
        try {
            return COSEKey.build(deviceKey).createPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse device key: " + e.getMessage(), e);
        }
    }

    private boolean tryVerifyDevice(
            COSESign1 originalSign1,
            PublicKey deviceKey,
            CBORItemList sessionTranscript,
            String docType,
            CBORItem deviceNameSpaces) {
        try {
            CBORItemList authData = new CBORItemList(
                    new CBORString("DeviceAuthentication"),
                    sessionTranscript,
                    new CBORString(docType),
                    deviceNameSpaces);
            byte[] payload = new CBORTaggedItem(24, new CBORByteArray(authData.encode())).encode();

            COSESign1 withPayload = new COSESign1(
                    originalSign1.getProtectedHeader(),
                    originalSign1.getUnprotectedHeader(),
                    new CBORByteArray(payload),
                    originalSign1.getSignature());
            return new COSEVerifier(deviceKey).verify(withPayload);
        } catch (Exception e) {
            LOG.debugf("Device signature verification attempt failed: %s", e.getMessage());
            return false;
        }
    }

    private void verifyDigests(CBORPairList mso, CBORPairList document) {
        CBORItem issuerSignedNameSpaces = val(map(document, "issuerSigned"), "nameSpaces");
        if (issuerSignedNameSpaces == null) return;
        if (!(issuerSignedNameSpaces instanceof CBORPairList nameSpaces)) {
            throw new IllegalStateException("issuerSigned.nameSpaces is not a map");
        }
        if (nameSpaces.getPairs().isEmpty()) return;
        CBORPairList valueDigests = map(mso, "valueDigests");
        if (valueDigests == null) {
            throw new IllegalStateException("MSO has no valueDigests for disclosed namespaces");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(javaDigestAlgorithm(str(mso, "digestAlgorithm")));
            for (var nsPair : nameSpaces.getPairs()) {
                String namespace = stringValue(nsPair.getKey());
                if (namespace == null || !(nsPair.getValue() instanceof CBORItemList elements)) {
                    throw new IllegalStateException("Malformed issuer-signed namespace");
                }
                verifyNamespaceDigests(valueDigests, namespace, elements, digest);
            }
        } catch (Exception e) {
            throw wrapIfNeeded(e, "Digest verification failed: ");
        }
    }

    private void verifyNamespaceDigests(
            CBORPairList valueDigests, String namespace, CBORItemList elements, MessageDigest digest) {
        CBORPairList nsDigests = map(valueDigests, namespace);
        if (nsDigests == null) {
            throw new IllegalStateException("MSO has no digests for namespace " + namespace);
        }

        for (CBORItem element : elements.getItems()) {
            verifyElementDigest(element, nsDigests, digest);
        }
    }

    private void verifyElementDigest(CBORItem element, CBORPairList nsDigests, MessageDigest digest) {
        CBORPairList item = unwrapTag24(element);
        CBORItem digestIdValue = item != null ? val(item, "digestID") : null;
        if (digestIdValue == null) {
            throw new IllegalStateException("Issuer-signed item has no digestID");
        }

        int digestId = intValue(digestIdValue);
        if (!(intKeyVal(nsDigests, digestId) instanceof CBORByteArray expected)) {
            throw new IllegalStateException("Missing digest for element " + digestId);
        }
        if (!Arrays.equals(digest.digest(element.encode()), expected.getValue())) {
            throw new IllegalStateException("Digest mismatch for element " + digestId);
        }
    }

    private void validateValidity(CBORPairList mso) {
        CBORPairList validityInfo = map(mso, "validityInfo");
        if (validityInfo == null) throw new IllegalStateException("MSO has no validityInfo");
        Instant now = Instant.now();

        Instant validFrom = parseInstant(val(validityInfo, "validFrom"));
        if (validFrom == null) throw new IllegalStateException("MSO validityInfo has no validFrom");
        if (validFrom.isAfter(now)) throw new IllegalStateException("Credential not yet valid");

        Instant validUntil = parseInstant(val(validityInfo, "validUntil"));
        if (validUntil == null) throw new IllegalStateException("MSO validityInfo has no validUntil");
        if (validUntil.isBefore(now)) throw new IllegalStateException("Credential expired");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> msoStatus(CBORPairList mso) {
        CBORItem status = val(mso, "status");
        if (status == null) return null;
        Object converted = cborToJava(status);
        if (!(converted instanceof Map<?, ?> map)) {
            throw new IllegalStateException("MSO status is not a map");
        }
        return (Map<String, Object>) map;
    }

    /** Maps the MSO digestAlgorithm (ISO/IEC 18013-5 9.1.2.5) to a JCA name; unknown values fail. */
    static String javaDigestAlgorithm(String msoDigestAlgorithm) {
        if (msoDigestAlgorithm == null) {
            throw new IllegalStateException("MSO has no digestAlgorithm");
        }
        return switch (msoDigestAlgorithm) {
            case "SHA-256" -> JavaAlgorithm.SHA256;
            case "SHA-384" -> JavaAlgorithm.SHA384;
            case "SHA-512" -> JavaAlgorithm.SHA512;
            default -> throw new IllegalStateException("Unsupported MSO digestAlgorithm: " + msoDigestAlgorithm);
        };
    }

    private Instant parseInstant(CBORItem value) {
        if (value == null) return null;
        try {
            if (value instanceof CBORTaggedItem tagged) {
                int tag = tagged.getTagNumber().intValue();
                if (tag == 0 || tag == CBOR_TAG_DATE) return Instant.parse(stringValue(tagged.getTagContent()));
            }
            if (value instanceof CBORString s) return Instant.parse(s.getValue());
            if (value instanceof CBORInteger i) return Instant.ofEpochSecond(i.getValue());
            if (value instanceof CBORLong l) return Instant.ofEpochSecond(l.getValue());
        } catch (Exception e) {
            LOG.debugf("Failed to parse validity timestamp: %s", e.getMessage());
        }
        return null;
    }

    private Object cborToJava(CBORItem item) {
        if (item == null) return null;
        return switch (item) {
            case CBORNull ignored -> null;
            case CBORTaggedItem tagged -> {
                int tag = tagged.getTagNumber().intValue();
                yield (tag == 0 || tag == CBOR_TAG_DATE)
                        ? stringValue(tagged.getTagContent())
                        : cborToJava(tagged.getTagContent());
            }
            case CBORString s -> s.getValue();
            case CBORInteger i -> (long) i.getValue();
            case CBORLong l -> l.getValue();
            case CBORBoolean b -> b.getValue();
            case CBORFloat f -> (double) f.getValue();
            case CBORDouble d -> d.getValue();
            case CBORByteArray b -> Base64.getUrlEncoder().withoutPadding().encodeToString(b.getValue());
            case CBORItemList list ->
                list.getItems().stream().map(this::cborToJava).toList();
            case CBORPairList map -> {
                Map<String, Object> result = new LinkedHashMap<>();
                for (var pair : map.getPairs()) {
                    String key = stringValue(pair.getKey());
                    result.put(key != null ? key : pair.getKey().toString(), cborToJava(pair.getValue()));
                }
                yield result;
            }
            default -> item.toString();
        };
    }

    private COSESign1 buildCoseSign1(CBORItem item) {
        try {
            if (item instanceof CBORByteArray bstr) item = decodeCbor(bstr.getValue());
            if (item instanceof CBORTaggedItem tagged && tagged.getTagNumber().intValue() == 18) {
                item = tagged.getTagContent();
            }
            return COSESign1.build(item);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse COSE_Sign1: " + e.getMessage(), e);
        }
    }

    private static CBORItem val(CBORPairList map, String key) {
        if (map == null || map.getPairs() == null) return null;
        for (var pair : map.getPairs()) {
            if (pair.getKey() instanceof CBORString s && s.getValue().equals(key)) return pair.getValue();
        }
        return null;
    }

    private static CBORItem intKeyVal(CBORPairList map, int key) {
        if (map == null || map.getPairs() == null) return null;
        for (var pair : map.getPairs()) {
            CBORItem k = pair.getKey();
            if (k instanceof CBORInteger ci && ci.getValue() == key) return pair.getValue();
            if (k instanceof CBORLong cl && cl.getValue() == key) return pair.getValue();
        }
        return null;
    }

    private static CBORPairList map(CBORPairList parent, String key) {
        return asMap(val(parent, key));
    }

    private static String str(CBORPairList map, String key) {
        return stringValue(val(map, key));
    }

    private static CBORPairList asMap(CBORItem item) {
        return item instanceof CBORPairList m ? m : null;
    }

    private static String stringValue(CBORItem item) {
        return item instanceof CBORString s ? s.getValue() : null;
    }

    private static int intValue(CBORItem item) {
        return switch (item) {
            case CBORInteger i -> i.getValue();
            case CBORLong l -> l.getValue().intValue();
            default -> throw new IllegalStateException("Expected integer, got: " + item);
        };
    }

    private static CBORItem decodeCbor(byte[] bytes) {
        try {
            io.github.suengineering.keycloak.oid4vp.util.CborLimits.check(bytes);
            return new CBORDecoder(bytes).next();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decode CBOR: " + e.getMessage(), e);
        }
    }

    private static IllegalStateException wrapIfNeeded(Exception e, String prefix) {
        if (e instanceof IllegalStateException ise) return ise;
        return new IllegalStateException(prefix + e.getMessage(), e);
    }

    private byte[] decodeBase64(String token) {
        try {
            return Base64.getUrlDecoder().decode(token);
        } catch (Exception e) {
            return Base64.getDecoder().decode(token);
        }
    }
}
