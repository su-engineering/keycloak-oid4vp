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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import javax.xml.XMLConstants;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.parsers.DocumentBuilderFactory;
import org.jboss.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Reads ETSI TS 119 612 trusted lists (XML, XAdES enveloped signature), including the EU list of
 * trusted lists (LOTL), which points to the national lists and names the certificates that sign them.
 *
 * <p>Only services whose type is explicitly accepted and whose current status is granted (or
 * recognised at national level) become trust anchors. Accepting a broad type such as qualified
 * certificate CAs would let any holder of a qualified certificate sign credentials, so the caller
 * must choose the types.
 */
final class Ts119612TrustList {

    private static final Logger LOG = Logger.getLogger(Ts119612TrustList.class);
    static final String TSL_NS = "http://uri.etsi.org/02231/v2#";
    static final String LOTL_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
    static final String TSL_MIME_TYPE = "application/vnd.etsi.tsl+xml";
    private static final Set<String> ACCEPTED_STATUSES = Set.of(
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel");
    static final int MAX_LISTS = 64;

    private Ts119612TrustList() {}

    /** One parsed list: its type, territory, next update, pointers (LOTL) and accepted services. */
    record Parsed(String type, String territory, Instant nextUpdate, List<Pointer> pointers, List<Service> services) {}

    record Pointer(
            String location,
            String type,
            String territory,
            String mimeType,
            List<X509Certificate> signingCertificates) {}

    record Service(String type, String status, List<X509Certificate> certificates) {}

    /** The anchors collected from a list, or from a LOTL and the national lists it points to. */
    record Result(List<X509Certificate> anchors, Instant nextUpdate, String type) {}

    static boolean looksLikeXml(String body) {
        String trimmed = body == null ? "" : body.stripLeading();
        if (trimmed.startsWith("﻿")) trimmed = trimmed.substring(1);
        return trimmed.startsWith("<");
    }

    /**
     * Verifies {@code xml} against {@code signingCertificates}, then collects anchors. A LOTL is
     * followed through {@code fetch} to the national lists of {@code territories} (all when empty).
     */
    static Result load(
            String xml,
            List<X509Certificate> signingCertificates,
            Set<String> serviceTypes,
            Set<String> territories,
            Function<String, String> fetch) {
        Document document = verifiedDocument(xml, signingCertificates);
        Parsed list = parse(document);
        if (!LOTL_TYPE.equals(list.type())) {
            return new Result(anchors(list, serviceTypes), list.nextUpdate(), list.type());
        }
        List<X509Certificate> anchors = new ArrayList<>();
        Instant nextUpdate = list.nextUpdate();
        int followed = 0;
        for (Pointer pointer : list.pointers()) {
            // Skip PDF copies and the LOTL's pointer to itself.
            if (!TSL_MIME_TYPE.equalsIgnoreCase(pointer.mimeType()) || LOTL_TYPE.equals(pointer.type())) continue;
            if (!territories.isEmpty()
                    && !territories.contains(pointer.territory().toUpperCase(Locale.ROOT))) continue;
            if (++followed > MAX_LISTS)
                throw new IllegalStateException("LOTL points to more than " + MAX_LISTS + " lists");
            try {
                Parsed national =
                        parse(verifiedDocument(fetch.apply(pointer.location()), pointer.signingCertificates()));
                if (national.nextUpdate() != null && !Instant.now().isBefore(national.nextUpdate())) {
                    // A lapsed national list contributes nothing, but must not take the others down.
                    LOG.warnf(
                            "Trusted list %s (%s) skipped: its NextUpdate %s has passed",
                            pointer.location(), pointer.territory(), national.nextUpdate());
                    continue;
                }
                anchors.addAll(anchors(national, serviceTypes));
                if (national.nextUpdate() != null
                        && (nextUpdate == null || national.nextUpdate().isBefore(nextUpdate))) {
                    nextUpdate = national.nextUpdate();
                }
            } catch (RuntimeException e) {
                // One unreachable or invalid national list must not drop the others.
                LOG.warnf("Trusted list %s (%s) skipped: %s", pointer.location(), pointer.territory(), e.getMessage());
            }
        }
        return new Result(List.copyOf(anchors), nextUpdate, list.type());
    }

    private static List<X509Certificate> anchors(Parsed list, Set<String> serviceTypes) {
        List<X509Certificate> anchors = new ArrayList<>();
        for (Service service : list.services()) {
            if (serviceTypes.contains(service.type()) && ACCEPTED_STATUSES.contains(service.status())) {
                anchors.addAll(service.certificates());
            }
        }
        return anchors;
    }

    /** Parses with DTDs and external entities disabled and checks the enveloped signature. */
    static Document verifiedDocument(String xml, List<X509Certificate> signingCertificates) {
        if (signingCertificates == null || signingCertificates.isEmpty()) {
            throw new IllegalStateException("No signing certificate to verify the trusted list with");
        }
        try {
            Document document = secureParse(xml);
            verifySignature(
                    document,
                    signer -> {
                        X5cChainValidator.validateCertChain(List.of(signer), signingCertificates);
                        return signer.getPublicKey();
                    },
                    signingCertificates);
            return document;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Trusted list signature invalid: " + e.getMessage(), e);
        }
    }

    interface SignerCheck {
        PublicKey keyFor(X509Certificate signer) throws Exception;
    }

    /**
     * Validates the single {@code ds:Signature} directly under the root. It must cover the whole
     * document ({@code URI=""} with the enveloped-signature transform), so everything read from the
     * document afterwards is signed.
     */
    static void verifySignature(Document document, SignerCheck signerCheck, List<X509Certificate> fallbackKeys)
            throws Exception {
        Element root = document.getDocumentElement();
        NodeList signatures = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (signatures.getLength() != 1 || signatures.item(0).getParentNode() != root) {
            throw new IllegalStateException("Expected exactly one signature directly under the root element");
        }
        registerIdAttributes(root);

        X509Certificate signer = keyInfoCertificate((Element) signatures.item(0));
        KeySelector selector;
        if (signer != null) {
            PublicKey key = signerCheck.keyFor(signer);
            selector = KeySelector.singletonKeySelector(key);
        } else {
            selector = new KeySelector() {
                @Override
                public KeySelectorResult select(
                        KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) {
                    // No certificate in KeyInfo: only the pinned certificates themselves can sign.
                    Key key = fallbackKeys.get(0).getPublicKey();
                    return () -> key;
                }
            };
            if (fallbackKeys.size() != 1) {
                throw new IllegalStateException("Signature has no certificate and several signing keys are configured");
            }
        }

        DOMValidateContext context = new DOMValidateContext(selector, signatures.item(0));
        context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
        XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
        if (!signature.validate(context)) {
            throw new IllegalStateException("signature does not verify");
        }
        boolean coversDocument = false;
        for (Object item : signature.getSignedInfo().getReferences()) {
            Reference reference = (Reference) item;
            if ("".equals(reference.getURI())) {
                for (Object transform : reference.getTransforms()) {
                    if (Transform.ENVELOPED.equals(((Transform) transform).getAlgorithm())) coversDocument = true;
                }
            }
        }
        if (!coversDocument) {
            throw new IllegalStateException("signature does not cover the whole document");
        }
    }

    private static X509Certificate keyInfoCertificate(Element signature) throws Exception {
        NodeList certificates = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
        if (certificates.getLength() == 0) return null;
        return certificate(certificates.item(0).getTextContent());
    }

    private static void registerIdAttributes(Element element) {
        if (element.hasAttribute("Id")) element.setIdAttribute("Id", true);
        if (element.hasAttribute("ID")) element.setIdAttribute("ID", true);
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element childElement) registerIdAttributes(childElement);
        }
    }

    static Parsed parse(Document document) {
        Element root = document.getDocumentElement();
        if (!TSL_NS.equals(root.getNamespaceURI()) || !"TrustServiceStatusList".equals(root.getLocalName())) {
            throw new IllegalStateException("Not an ETSI TS 119 612 TrustServiceStatusList");
        }
        Element scheme = child(root, "SchemeInformation");
        if (scheme == null) throw new IllegalStateException("Trusted list has no SchemeInformation");
        String type = text(child(scheme, "TSLType"));
        String territory = text(child(scheme, "SchemeTerritory"));
        Instant nextUpdate = null;
        Element next = child(scheme, "NextUpdate");
        if (next != null && child(next, "dateTime") != null) nextUpdate = Instant.parse(text(child(next, "dateTime")));

        List<Pointer> pointers = new ArrayList<>();
        Element pointerList = child(scheme, "PointersToOtherTSL");
        if (pointerList != null) {
            for (Element pointer : children(pointerList, "OtherTSLPointer")) {
                String location = text(child(pointer, "TSLLocation"));
                String mimeType = null;
                String pointerType = null;
                String pointerTerritory = null;
                for (Element info : descendants(pointer, "OtherInformation")) {
                    for (Node n = info.getFirstChild(); n != null; n = n.getNextSibling()) {
                        if (!(n instanceof Element value)) continue;
                        if ("MimeType".equals(value.getLocalName()))
                            mimeType = value.getTextContent().trim();
                        if ("TSLType".equals(value.getLocalName()))
                            pointerType = value.getTextContent().trim();
                        if ("SchemeTerritory".equals(value.getLocalName()))
                            pointerTerritory = value.getTextContent().trim();
                    }
                }
                pointers.add(new Pointer(
                        location,
                        pointerType,
                        pointerTerritory == null ? "" : pointerTerritory,
                        mimeType,
                        certificates(pointer)));
            }
        }

        List<Service> services = new ArrayList<>();
        Element providers = child(root, "TrustServiceProviderList");
        if (providers != null) {
            for (Element provider : children(providers, "TrustServiceProvider")) {
                Element tspServices = child(provider, "TSPServices");
                if (tspServices == null) continue;
                for (Element service : children(tspServices, "TSPService")) {
                    Element information = child(service, "ServiceInformation");
                    if (information == null) continue;
                    services.add(new Service(
                            text(child(information, "ServiceTypeIdentifier")),
                            text(child(information, "ServiceStatus")),
                            certificates(child(information, "ServiceDigitalIdentity"))));
                }
            }
        }
        return new Parsed(type, territory, nextUpdate, List.copyOf(pointers), List.copyOf(services));
    }

    private static List<X509Certificate> certificates(Element scope) {
        List<X509Certificate> certificates = new ArrayList<>();
        if (scope == null) return certificates;
        for (Element element : descendants(scope, "X509Certificate")) {
            if (!TSL_NS.equals(element.getNamespaceURI())) continue;
            try {
                certificates.add(certificate(element.getTextContent()));
            } catch (Exception e) {
                LOG.debugf("Unreadable certificate in trusted list: %s", e.getMessage());
            }
        }
        return certificates;
    }

    private static X509Certificate certificate(String base64) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(base64.trim());
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    private static Document secureParse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static Element child(Element parent, String localName) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && localName.equals(e.getLocalName())) return e;
        }
        return null;
    }

    private static List<Element> children(Element parent, String localName) {
        List<Element> out = new ArrayList<>();
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && localName.equals(e.getLocalName())) out.add(e);
        }
        return out;
    }

    private static List<Element> descendants(Element parent, String localName) {
        List<Element> out = new ArrayList<>();
        NodeList nodes = parent.getElementsByTagNameNS("*", localName);
        for (int i = 0; i < nodes.getLength(); i++) out.add((Element) nodes.item(i));
        return out;
    }

    private static String text(Element element) {
        return element == null ? null : element.getTextContent().trim();
    }
}
