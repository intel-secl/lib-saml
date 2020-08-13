/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.SamlUtil;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.mtwilson.xml.XML;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.parsers.ParserConfigurationException;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Statement;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * This class extracts trust information from a SAML assertion.
 *
 * Before using the assertions contained within a TrustAssertion object, you
 * must call isValid() to find out if the provided assertion is valid. If it is,
 * you can call getSubject(), getIssuer(), getAttributeNames(), and
 * getStringAttribute(), etc. If isValid() returns false, you can call error()
 * to get the Exception object that describes the validation error.
 *
 * See also http://ws.apache.org/wss4j/config.html
 *
 * @author jbuhacoff (original author)
 * @author srege
 */
public class TrustAssertion {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private Assertion assertion;
    private HashMap<String, HostTrustAssertion> hostAssertionMap; //   host ->  Map of assertions about the host
    private boolean isValid;
    private Exception error;

    /**
     * Trusted SAML-signing certificates in the keystore must be marked for this
     * trusted purpose with the tag "(saml)" or "(SAML)" at the end of their
     * alias.
     *
     * @param trustedSigners X509Certificate[] key store with at least one trusted certificate with
     * the "(saml)" tag in its alias
     * @param xml returned from attestation service
     
     */
    public TrustAssertion(X509Certificate[] trustedSigners, String xml) {
        try {
            // is the xml signed by a trusted signer?
            Element document = readXml(xml);
            SamlUtil verifier = new SamlUtil(); // ClassNotFoundException, InstantiationException, IllegalAccessException
            boolean isVerified = verifier.verifySAMLSignature(document, trustedSigners);
            
            if (isVerified) {
                log.info("Validated signature in xml document");
                // populate assertions map
                InitializationService.initialize(); // required to load default configs that ship with opensaml that specify how to build and parse the xml (if you don't do this you will get a null unmarshaller when you try to parse xml)
                assertion = readAssertion(document); // ParserConfigurationException, SAXException, IOException, UnmarshallingException
                hostAssertionMap = new HashMap<String, HostTrustAssertion>();
                populateAssertionMap();
                isValid = true;
                error = null;
            } else {
                throw new IllegalArgumentException("Cannot verify XML signature");
            }
        } catch (Exception e) {
            log.error("Cannot verify trust assertion", e);
            isValid = false;
            error = e;
            assertion = null;
            hostAssertionMap = null;
        }
    }

    public boolean isValid() {
        return isValid;
    }

    /**
     *
     * @return null if assertion is valid, otherwise an exception object
     * describing the error
     */
    public Exception error() {
        return error;
    }

    /**
     *
     * @return the OpenSAML Assertion object, or null if there was an error
     */
    public Assertion getAssertion() {
        return assertion;
    }

    /**
     * @return the assertion's issue instant
     * @since 0.5.3
     */
    public Date getDate() {
        return assertion.getIssueInstant().toDate();
    }

    /**
     *
     * @return the earliest "not after" date of any subject confirmation
     * included in the saml report, OR null if no such date was found
     */
    public Date getNotAfter() {
        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        Date notAfter = null;
        if (subjectConfirmations != null) {
            for (SubjectConfirmation subjectConfirmation : subjectConfirmations) {
                SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
                if (subjectConfirmationData != null) {
                    DateTime subjectNotOnOrAfterDateTime = subjectConfirmationData.getNotOnOrAfter();
                    if (subjectNotOnOrAfterDateTime != null) {
                        Date subjectNotOnOrAfter = subjectNotOnOrAfterDateTime.toDate();
                        if (notAfter == null || notAfter.after(subjectNotOnOrAfter)) {
                            notAfter = subjectNotOnOrAfter;
                        }
                    }
                }
            }
        }
        return notAfter;
    }

    public Set<String> getHosts() {
        return hostAssertionMap.keySet();
    }

    public HostTrustAssertion getTrustAssertion(String hostname) {
        return hostAssertionMap.get(hostname);
    }

    public static class HostTrustAssertion {

        private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(HostTrustAssertion.class);
        private Assertion assertion;
        private Map<String, String> assertionMap; // attributes for a single host

        public HostTrustAssertion(Assertion assertion, Map<String, String> assertionMap) {
            this.assertion = assertion;
            this.assertionMap = assertionMap;
        }

        /**
         * @return the assertion's issue instant
         * @since 0.5.3
         */
        public Date getDate() {
            return assertion.getIssueInstant().toDate();
        }

        /**
         *
         * @return the assertion subject's AIK public key
         * @throws NullPointerException if isValid() == false
         */
        public String getSubject() {
            return assertionMap.get("Host_Name");
        }

        /**
         *
         * @return the assertion subject's format
         * @throws NullPointerException if isValid() == false
         */
        public String getSubjectFormat() {
            return "hostname";
        }

        /**
         *
         * @return the assertion issuer
         * @throws NullPointerException if isValid() == false
         */
        public String getIssuer() {
            return assertion.getIssuer().getValue();
        }

        /**
         *
         * @return a set of the available attribute names in the assertion
         * @throws NullPointerException if isValid() == false
         */
        public Set<String> getAttributeNames() {
            HashSet<String> names = new HashSet<String>();
            names.addAll(assertionMap.keySet());
            return names;
        }

        /**
         *
         * @param name
         * @return the value of the named attribute
         * @throws NullPointerException if isValid() == false
         */
        public String getStringAttribute(String name) {
            return assertionMap.get(name);
        }

        public X509Certificate getAikCertificate() throws CertificateException {
            String pem = assertionMap.get("AIK_Certificate");
            if (pem == null || pem.isEmpty()) {
                return null;
            }
            try {
                byte[] aikCertData = Base64.getDecoder().decode(pem);
                CertificateFactory cf1 = CertificateFactory.getInstance("X509");
                X509Certificate cert = (X509Certificate) cf1.generateCertificate(new ByteArrayInputStream(aikCertData));
                return cert;
            } catch (CertificateException e) {
                log.debug("Error while getting aik certificate: " + e.toString(), e);
            }
            return null;
        }

        public PublicKey getAikPublicKey() throws CryptographyException {
            // if there's an aik certificate, get the public key from there
            try {
                X509Certificate cert = getAikCertificate();
                if (cert != null) {
                    return cert.getPublicKey();
                }
            } catch (Exception e) {
                log.debug("Error while getting aik certificate: " + e.toString(), e);
                // but we keep going to try the aik public key field
            }
            // otherwise, look for a public key field
            String pem = assertionMap.get("AIK_PublicKey");
            if (pem == null || pem.isEmpty()) {
                return null;
            }
            PublicKey publicKey = RsaUtil.decodePemPublicKey(pem);
            return publicKey;
        }

        public X509Certificate getBindingKeyCertificate() throws CertificateException {
            String pem = assertionMap.get("Binding_Key_Certificate");
            if (pem == null || pem.isEmpty()) {
                return null;
            }
             try {
                byte[] bkCertData = Base64.getDecoder().decode(pem);
                CertificateFactory cf1 = CertificateFactory.getInstance("X509");
                X509Certificate cert = (X509Certificate) cf1.generateCertificate(new ByteArrayInputStream(bkCertData));
                return cert;
            } catch (CertificateException e) {
                log.debug("Error while getting binding key certificate: " + e.toString(), e);
            }
             return null;
        }

        public String getTPMVersion(){
            String tpmVersion = assertionMap.get("TPMVersion");
            return tpmVersion;
        }

        public String getVMMOSName() {
            String vmm_osname = assertionMap.get("OSName");
            return vmm_osname;
        }

        public boolean isHostTrusted() {
            String trusted = assertionMap.get("TRUST_OVERALL");
            return trusted != null && trusted.equalsIgnoreCase("true");
        }

        public boolean isHostBiosTrusted() {
            String trusted = assertionMap.get("TRUST_PLATFORM");
            return trusted != null && trusted.equalsIgnoreCase("true");
        }

        public boolean isHostVmmTrusted() {
            String trusted = assertionMap.get("Trusted_VMM");
            return trusted != null && trusted.equalsIgnoreCase("true");
        }

        public boolean isHostLocationTrusted() {
            String trusted = assertionMap.get("TRUST_ASSET_TAG");
            return trusted != null && trusted.equalsIgnoreCase("true");
        }
    }

    /**
     * See also {@code XML.parseDocumentElement} in mtwilson-util-xml
     */
    private Element readXml(String xmlDocument) throws ParserConfigurationException, SAXException, IOException {
        XML xml = new XML();
        xml.setSchemaPackageName("xsd");
        xml.addSchemaLocation("http://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd");
        xml.addSchemaLocation("http://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd");
        xml.addSchemaLocation("http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd");
        xml.addSchemaLocation("http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd");
        return xml.parseDocumentElement(xmlDocument);
    }

    private Assertion readAssertion(Element document) throws UnmarshallingException {
        log.debug("Reading assertion from element {}", document.getTagName());
        UnmarshallerFactory factory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        Unmarshaller unmarshaller = factory.getUnmarshaller(document);
        XMLObject xml = unmarshaller.unmarshall(document); // UnmarshallingException
        Assertion samlAssertion = (Assertion) xml;
        return samlAssertion;
    }

    /**
     * Sample assertion statements that may appear in the XML: Trusted (boolean)
     * Trusted_PLATFORM (boolean) Trusted_VMM (boolean) BIOS_Name (string)
     * BIOS_Version (string) BIOS_OEM (string) VMM_Name (string) VMM_Version
     * (string) VMM_OSName (string) VMM_OSVersion (string) The BIOS_* entries
     * will only appear if Trusted_PLATFORM is true The VMM_* entries will only
     * appear if Trusted_VMM is true
     */
    private void populateAssertionMap() {
        for (Statement statement : assertion.getStatements()) {
            if (statement instanceof AttributeStatement) {
                HashMap<String, String> assertionMap = new HashMap<String, String>();
                HostTrustAssertion hostTrustAssertion = new HostTrustAssertion(assertion, assertionMap);
                for (Attribute attribute
                        : ((AttributeStatement) statement).getAttributes()) {
                    String attributeValue = null;
                    for (XMLObject value : attribute.getAttributeValues()) {
                        if (value instanceof XSAny) {
                            attributeValue = (((XSAny) value).getTextContent()); // boolean attributes are the text "true" or "false"
                        }
                        if (value instanceof XSString) {
                            attributeValue = (((XSString) value).getValue());
                        }
                    }
                    assertionMap.put(attribute.getName(), attributeValue);
                }
                hostAssertionMap.put(assertionMap.get("HostName"), hostTrustAssertion);
            }
        }
    }
}
