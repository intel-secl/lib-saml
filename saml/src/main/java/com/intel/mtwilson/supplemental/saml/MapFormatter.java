/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;



import com.intel.mtwilson.core.common.tag.model.X509AttributeCertificate;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import net.shibboleth.utilities.java.support.xml.ElementSupport;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.core.xml.config.XMLConfigurationException;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.w3c.dom.Element;

/**
 * Generates assertion v=based on input provided by user
 * @author srege
 */
public class MapFormatter implements AssertionFormatter {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MapFormatter.class);

 
    public Map<String, String> userData;
    public X509AttributeCertificate tagCertificate;
   
    private final XMLObjectBuilderFactory builderFactory;
    private  SamlAssertion samlAssertion;
    private  SAMLSignature signatureGenerator;


  

    private static class XMLObjectBuilderFactoryHolder {

        private static final XMLObjectBuilderFactory builderFactory = createBuilderFactory();

        private static XMLObjectBuilderFactory createBuilderFactory() {
            try {
                // OpenSAML 2.3
                InitializationService.initialize();
                return XMLObjectProviderRegistrySupport.getBuilderFactory();
            } catch (InitializationException e) {
                throw new IllegalStateException("Cannot initialize OpenSAML", e);
            }
        }
    }

    public MapFormatter(Map<String, String> userData) {
       
        this.userData = userData;
        this.builderFactory = XMLObjectBuilderFactoryHolder.builderFactory;

    }
    
  /**Creates assertion based on input provided by user
     * @param issuerConfiguration IssuerConfiguration 
     * @param assertion Assertion 
     * @return assertion
   */
    @Override
    public SamlAssertion generateAssertion(IssuerConfiguration issuerConfiguration,Assertion assertion) throws MarshallingException, GeneralSecurityException, XMLSignatureException, MarshalException{
        samlAssertion = new SamlAssertion();
         try {
            signatureGenerator = new SAMLSignature(issuerConfiguration);
        } catch (ReflectiveOperationException | GeneralSecurityException | IOException ex) {
            log.error("Cannot load SAML signature generator: " + ex.getMessage(), ex);
            try {
                throw new InitializationException("Failed to initialize SAML signature generator", ex);
            } catch (InitializationException ex1) {
                Logger.getLogger(MapFormatter.class.getName()).log(Level.SEVERE, null, ex1);
            }
        }
        SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        assertion = (Assertion) assertionBuilder.buildObject();
       
        // add host attributes (both for single host and multi-host assertions)

     //   assertion.setIssuer(createIssuer(issuerConfiguration));
        log.debug("Call to applyTo in MapFormatter successful");
        DateTime now = new DateTime();
        assertion.setID("MapAssertion");
        log.debug("ID set for assertion");
        assertion.setIssueInstant(now);
        assertion.setVersion(SAMLVersion.VERSION_20);
        SAMLObjectBuilder issuerBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = (Issuer) issuerBuilder.buildObject();
        issuer.setValue(issuerConfiguration.getIssuerName());
        assertion.setIssuer(issuer);
        log.debug("Issuer created in assertion ",assertion.getIssuer());
        try {
            log.debug("Hostname is {}",userData.get("hostName"));
            assertion.setSubject(createSubject(userData.get("hostName"),issuerConfiguration));
        } catch (InitializationException ex) {
            Logger.getLogger(MapFormatter.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnknownHostException ex) {
            Logger.getLogger(MapFormatter.class.getName()).log(Level.SEVERE, null, ex);
        }

         log.debug("Creating string attributes for key-value pair in Map");
         assertion.getAttributeStatements().add(createAttributes());
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion);

        Element plaintextElement = marshaller.marshall(assertion);
        String originalAssertionString = SerializeSupport.nodeToString(plaintextElement);
        log.debug("Assertion String with Code review changes suggested : " + originalAssertionString);
        signAssertion(plaintextElement);
        samlAssertion.assertion = SerializeSupport.nodeToString(plaintextElement);
        return samlAssertion;
        
    }
 /**
     * Creates String attributes for provided name ,value pair
     * @param name, value
     * @return attr
     */
   private AttributeStatement createAttributes() {
       SAMLObjectBuilder attrStatementBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement attrStatement = (AttributeStatement) attrStatementBuilder.buildObject();
        for (Map.Entry<String, String> entry : userData.entrySet()) {
          attrStatement.getAttributes().add(createStringAttribute(entry.getKey(), entry.getValue()));
        }
       
        
        return attrStatement;
    }
    private Attribute createStringAttribute(String name, String value) {
        SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        Attribute attr = (Attribute) attrBuilder.buildObject();
        attr.setName(name);

        XMLObjectBuilder xmlBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
        XSString attrValue = (XSString) xmlBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attrValue.setValue(value);

        attr.getAttributeValues().add(attrValue);
        return attr;
    }
    private Subject createSubject(String hostName,IssuerConfiguration issuerConfiguration) throws InitializationException, UnknownHostException {
        SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = (Subject) subjectBuilder.buildObject();
        log.debug("Inside Create Subject");
        subject.setNameID(createNameID(hostName));
        log.debug("NameID was created successfully");
        subject.getSubjectConfirmations().add(createSubjectConfirmation(issuerConfiguration));
        return subject;
    }
   
       private NameID createNameID(String hostName) {
           SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = (NameID) nameIdBuilder.buildObject();
        nameId.setValue(hostName);
        log.debug("Inside createNameID {}",nameId.getValue());
//            nameId.setNameQualifier(input.getStrNameQualifier()); optional:  
        nameId.setFormat(NameID.UNSPECIFIED); // !!! CAN ALSO USE X509 SUBJECT FROM HOST CERTIFICATE instead of host name in database   
        return nameId;
    }
        private SubjectConfirmation createSubjectConfirmation(IssuerConfiguration issuerConfiguration) throws InitializationException, UnknownHostException {
            SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = (SubjectConfirmation) subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);
        subjectConfirmation.setSubjectConfirmationData(createSubjectConfirmationData(issuerConfiguration));
        // Create the NameIdentifier
            SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = (NameID) nameIdBuilder.buildObject();
        nameId.setValue(issuerConfiguration.getIssuerServiceName());
        log.debug("Inside createSubject Confirmation {}",nameId.getValue());
        nameId.setFormat(NameID.UNSPECIFIED); // !!! CAN ALSO USE X509 SUBJECT FROM HOST CERTIFICATE instead of host name in database   
        subjectConfirmation.setNameID(nameId);
        return subjectConfirmation;
    }
       private SubjectConfirmationData createSubjectConfirmationData(IssuerConfiguration issuerConfiguration) throws InitializationException, UnknownHostException {
           SAMLObjectBuilder confirmationMethodBuilder = (SAMLObjectBuilder)  builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
            SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) confirmationMethodBuilder.buildObject();
            DateTime now = new DateTime();
            // Required to add to cache
            samlAssertion.created_ts = now.toDate();
            if(samlAssertion != null)
                log.debug("Created samlAssertion with TS {}",samlAssertion.created_ts);
            confirmationMethod.setNotBefore(now); 
            if( issuerConfiguration.getValiditySeconds() != null && samlAssertion != null) {
                confirmationMethod.setNotOnOrAfter(now.plusSeconds(issuerConfiguration.getValiditySeconds()));
                log.debug("IssuerConfiguration validity seconds not null {}",issuerConfiguration.getValiditySeconds());
                // Required to add to cache
                samlAssertion.expiry_ts = confirmationMethod.getNotOnOrAfter().toDate();
            }
            // SubjectConfirmationData not required to have Address, and the
            // Java API here is doing a DNS lookup to get the address. If the
            // local host name is not in /etc/hosts or configured in DNS, this
            // will fail. 
            // If we need to restore host address, use "mtwilson.host" configuration
            // setting instead of performing a lookup here.
            //InetAddress localhost = InetAddress.getLocalHost();
            //confirmationMethod.setAddress(localhost.getHostAddress()); // NOTE: This is the ATTESTATION SERVICE IP ADDRESS,  **NOT** THE HOST ADDRESS
            return confirmationMethod;
        }
       private void signAssertion(Element value) throws GeneralSecurityException, XMLSignatureException, MarshalException {
        signatureGenerator.signSAMLObject(value);

    }
    
}
