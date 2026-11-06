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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

class Ts119612TrustListTest {

    private static final String EAA_Q = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q";
    private static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    private static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    private static final String WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    private static final String GENERIC = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";

    private Signer lotlOperator;
    private Signer deOperator;
    private Signer nlOperator;
    private X509Certificate eaaIssuerCa;
    private X509Certificate withdrawnCa;
    private X509Certificate qualifiedCa;

    @BeforeEach
    void setUp() throws Exception {
        lotlOperator = new Signer("CN=EU LOTL operator");
        deOperator = new Signer("CN=DE TL operator");
        nlOperator = new Signer("CN=NL TL operator");
        eaaIssuerCa = new Signer("CN=QEAA provider CA").certificate;
        withdrawnCa = new Signer("CN=Withdrawn QEAA CA").certificate;
        qualifiedCa = new Signer("CN=QC CA").certificate;
    }

    @Test
    void theRealEuLotlSignatureVerifies() throws Exception {
        String xml = Files.readString(Path.of("src/test/resources/tsl/eu-lotl.xml"));
        Document document = parseForTest(xml);

        // Pins the certificate from KeyInfo itself: this checks the XAdES/XMLDSig processing, not the pin.
        Ts119612TrustList.verifySignature(document, X509Certificate::getPublicKey, List.of());
        Ts119612TrustList.Parsed lotl = Ts119612TrustList.parse(document);

        assertThat(lotl.type()).isEqualTo(Ts119612TrustList.LOTL_TYPE);
        assertThat(lotl.pointers())
                .filteredOn(p -> "DE".equals(p.territory()) && Ts119612TrustList.TSL_MIME_TYPE.equals(p.mimeType()))
                .singleElement()
                .satisfies(de -> {
                    assertThat(de.location()).startsWith("https://");
                    assertThat(de.signingCertificates()).isNotEmpty();
                });
    }

    @Test
    void aTamperedEuLotlIsRejected() throws Exception {
        String xml = Files.readString(Path.of("src/test/resources/tsl/eu-lotl.xml"))
                .replace("https://tl.bundesnetzagentur.de/TL-DE.xml", "https://attacker.example/TL-DE.xml");
        Document document = parseForTest(xml);

        assertThatThrownBy(() -> Ts119612TrustList.verifySignature(document, X509Certificate::getPublicKey, List.of()))
                .hasMessageContaining("does not verify");
    }

    @Test
    void onlyGrantedServicesOfConfiguredTypesAnchor() throws Exception {
        String list = deOperator.sign(nationalList("DE"));

        Ts119612TrustList.Result result =
                Ts119612TrustList.load(list, List.of(deOperator.certificate), Set.of(EAA_Q), Set.of(), url -> null);

        assertThat(result.anchors()).containsExactly(eaaIssuerCa);
        assertThat(result.type()).isEqualTo(GENERIC);
        assertThat(result.nextUpdate()).isAfter(Instant.now());
    }

    @Test
    void lotlIsFollowedToTheNationalListsWithThePointerCertificates() throws Exception {
        Map<String, String> served = Map.of(
                "https://tl.example/de.xml", deOperator.sign(nationalList("DE")),
                // Signed by the wrong operator: the pointer names nlOperator.
                "https://tl.example/nl.xml", deOperator.sign(nationalList("NL")));
        String lotl = lotlOperator.sign(lotl(
                pointer("https://tl.example/de.xml", "DE", deOperator.certificate),
                pointer("https://tl.example/nl.xml", "NL", nlOperator.certificate)));

        Ts119612TrustList.Result all =
                Ts119612TrustList.load(lotl, List.of(lotlOperator.certificate), Set.of(EAA_Q), Set.of(), served::get);
        assertThat(all.anchors()).as("NL is skipped, DE still loads").containsExactly(eaaIssuerCa);

        Ts119612TrustList.Result nlOnly = Ts119612TrustList.load(
                lotl, List.of(lotlOperator.certificate), Set.of(EAA_Q), Set.of("NL"), served::get);
        assertThat(nlOnly.anchors()).isEmpty();
    }

    @Test
    void aListSignedByAnyoneElseIsRejected() throws Exception {
        String list = nlOperator.sign(nationalList("DE"));

        assertThatThrownBy(() -> Ts119612TrustList.load(
                        list, List.of(deOperator.certificate), Set.of(EAA_Q), Set.of(), u -> null))
                .hasMessageContaining("not anchored");
    }

    @Test
    void unsignedListsAndDoctypesAreRejected() throws Exception {
        assertThatThrownBy(() -> Ts119612TrustList.load(
                        nationalList("DE"), List.of(deOperator.certificate), Set.of(EAA_Q), Set.of(), u -> null))
                .hasMessageContaining("exactly one signature");
        String withDoctype = "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>" + nationalList("DE");
        assertThatThrownBy(() -> Ts119612TrustList.load(
                        withDoctype, List.of(deOperator.certificate), Set.of(EAA_Q), Set.of(), u -> null))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aSignatureThatDoesNotCoverTheWholeDocumentIsRejected() throws Exception {
        // Sign only SchemeInformation, then rely on unsigned services: a wrapping attempt.
        String partial = deOperator.signReference(nationalList("DE"), "#scheme");

        assertThatThrownBy(() -> Ts119612TrustList.load(
                        partial, List.of(deOperator.certificate), Set.of(EAA_Q), Set.of(), u -> null))
                .hasMessageContaining("whole document");
    }

    @Test
    void trustListProviderReadsXmlLists() throws Exception {
        String list = deOperator.sign(nationalList("DE"));
        TrustListProvider provider = new TrustListProvider(
                null,
                "https://tl.example/de-" + System.nanoTime() + ".xml",
                Duration.ofMinutes(5),
                Duration.ZERO,
                List.of(deOperator.certificate),
                false) {
            @Override
            protected FetchedTrustList fetchTrustListJwt() {
                return new FetchedTrustList(list, null);
            }
        }.withXmlTrustedListOptions(Set.of(EAA_Q), Set.of());

        assertThat(provider.getIssuanceCertificates()).containsExactly(eaaIssuerCa);
        assertThat(provider.getCurrentLoTEType()).isEqualTo(GENERIC);
    }

    private String nationalList(String territory) throws Exception {
        return "<TrustServiceStatusList xmlns=\"" + Ts119612TrustList.TSL_NS + "\" Id=\"tsl\">"
                + "<SchemeInformation Id=\"scheme\"><TSLVersionIdentifier>6</TSLVersionIdentifier>"
                + "<TSLType>" + GENERIC + "</TSLType><SchemeTerritory>" + territory + "</SchemeTerritory>"
                + "<NextUpdate><dateTime>"
                + Instant.now().plus(30, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS) + "</dateTime></NextUpdate>"
                + "</SchemeInformation><TrustServiceProviderList><TrustServiceProvider><TSPServices>"
                + service(EAA_Q, GRANTED, eaaIssuerCa)
                + service(EAA_Q, WITHDRAWN, withdrawnCa)
                + service(CA_QC, GRANTED, qualifiedCa)
                + "</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>";
    }

    private static String service(String type, String status, X509Certificate certificate) throws Exception {
        return "<TSPService><ServiceInformation><ServiceTypeIdentifier>" + type + "</ServiceTypeIdentifier>"
                + "<ServiceStatus>" + status + "</ServiceStatus><ServiceDigitalIdentity><DigitalId><X509Certificate>"
                + Base64.getEncoder().encodeToString(certificate.getEncoded())
                + "</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceInformation></TSPService>";
    }

    private static String lotl(String... pointers) {
        return "<TrustServiceStatusList xmlns=\"" + Ts119612TrustList.TSL_NS + "\" Id=\"lotl\"><SchemeInformation>"
                + "<TSLType>" + Ts119612TrustList.LOTL_TYPE + "</TSLType><SchemeTerritory>EU</SchemeTerritory>"
                + "<PointersToOtherTSL>" + String.join("", pointers) + "</PointersToOtherTSL>"
                + "<NextUpdate><dateTime>"
                + Instant.now().plus(60, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS) + "</dateTime></NextUpdate>"
                + "</SchemeInformation></TrustServiceStatusList>";
    }

    private static String pointer(String location, String territory, X509Certificate signer) throws Exception {
        return "<OtherTSLPointer><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>"
                + Base64.getEncoder().encodeToString(signer.getEncoded())
                + "</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>"
                + "<TSLLocation>" + location + "</TSLLocation><AdditionalInformation>"
                + "<OtherInformation><TSLType>" + GENERIC + "</TSLType></OtherInformation>"
                + "<OtherInformation><SchemeTerritory>" + territory + "</SchemeTerritory></OtherInformation>"
                + "<OtherInformation><MimeType xmlns=\"http://uri.etsi.org/02231/v2/additionaltypes#\">"
                + Ts119612TrustList.TSL_MIME_TYPE + "</MimeType></OtherInformation>"
                + "</AdditionalInformation></OtherTSLPointer>";
    }

    private static Document parseForTest(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    /** A list operator: a self-signed P-256 certificate that signs lists with an enveloped XMLDSig. */
    private static final class Signer {
        final KeyPair keys;
        final X509Certificate certificate;

        Signer(String subject) throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            keys = generator.generateKeyPair();
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Principal(subject),
                    BigInteger.valueOf(System.nanoTime()),
                    Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                    Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                    new X500Principal(subject),
                    keys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certificate = new JcaX509CertificateConverter()
                    .getCertificate(
                            builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
        }

        String sign(String xml) throws Exception {
            return signReference(xml, "");
        }

        String signReference(String xml, String uri) throws Exception {
            Document document = parseForTest(xml);
            Element root = document.getDocumentElement();
            if (root.hasAttribute("Id")) root.setIdAttribute("Id", true);
            Element scheme = (Element) root.getElementsByTagNameNS(Ts119612TrustList.TSL_NS, "SchemeInformation")
                    .item(0);
            if (scheme.hasAttribute("Id")) scheme.setIdAttribute("Id", true);
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            List<Transform> transforms = uri.isEmpty()
                    ? List.of(
                            factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                            factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null))
                    : List.of(factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));
            Reference reference = factory.newReference(
                    uri, factory.newDigestMethod(DigestMethod.SHA256, null), transforms, null, null);
            SignedInfo signedInfo = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", null),
                    Collections.singletonList(reference));
            KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
            var keyInfo = keyInfoFactory.newKeyInfo(List.of(keyInfoFactory.newX509Data(List.of(certificate))));
            factory.newXMLSignature(signedInfo, keyInfo).sign(new DOMSignContext(keys.getPrivate(), root));
            StringWriter out = new StringWriter();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(out));
            return out.toString();
        }
    }
}
