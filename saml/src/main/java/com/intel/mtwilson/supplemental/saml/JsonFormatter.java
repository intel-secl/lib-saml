/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import net.shibboleth.utilities.java.support.xml.ElementSupport;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.config.InitializationException;
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
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class JsonFormatter
  implements AssertionFormatter
{
  private static final org.slf4j.Logger log = LoggerFactory.getLogger(JsonFormatter.class);
  public JsonObject jsonObject;
    private final XMLObjectBuilderFactory builderFactory;
   
  public String key;
  public String jsonString;
  private SamlAssertion samlAssertion;
  private SAMLSignature signatureGenerator;
  
  private static class XMLObjectBuilderFactoryHolder
  {

         private static final XMLObjectBuilderFactory builderFactory = createBuilderFactory();

   
    
    private static XMLObjectBuilderFactory createBuilderFactory()
    {
      try
      {
        InitializationService.initialize();
        return XMLObjectProviderRegistrySupport.getBuilderFactory();

      }
      catch (InitializationException e)
      {
        throw new IllegalStateException("Cannot initialize OpenSAML", e);
      }
    }
  }
  
  public JsonFormatter(String key, JsonObject jsonObject)
  {
    this.key = key;
    this.jsonObject = jsonObject;
    this.builderFactory = XMLObjectBuilderFactoryHolder.builderFactory;
  }
  
  public SamlAssertion generateAssertion(IssuerConfiguration issuerConfiguration, Assertion assertion)
    throws GeneralSecurityException, MarshallingException, XMLSignatureException, MarshalException
  {
    samlAssertion = new SamlAssertion();
   
    try
    {
      signatureGenerator = new SAMLSignature(issuerConfiguration);
    }
    catch (ReflectiveOperationException|GeneralSecurityException|IOException ex)
    {
      log.error("Cannot load SAML signature generator: " + ex.getMessage(), ex);
      try
      {
        throw new InitializationException("Failed to initialize SAML signature generator", ex);
      }
      catch (InitializationException ex1)
      {
        java.util.logging.Logger.getLogger(MapFormatter.class.getName()).log(Level.SEVERE, null, ex1);
      }
    }
    SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
    assertion = (Assertion)assertionBuilder.buildObject();
    log.debug("Inside JSON Formatter");
    DateTime now = new DateTime();
    assertion.setIssueInstant(now);
    assertion.setVersion(SAMLVersion.VERSION_20);
    assertion.setID("JSONAssertion");
    SAMLObjectBuilder issuerBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
    Issuer issuer = (Issuer)issuerBuilder.buildObject();
    issuer.setValue(issuerConfiguration.getIssuerName());
    assertion.setIssuer(issuer);
    try
    {
      assertion.setSubject(createSubject(key, issuerConfiguration));
    }
    catch (InitializationException ex)
    {
      java.util.logging.Logger.getLogger(JsonFormatter.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (UnknownHostException ex)
    {
      java.util.logging.Logger.getLogger(JsonFormatter.class.getName()).log(Level.SEVERE, null, ex);
    }
    Gson gson = new Gson();
    jsonString = gson.toJson(jsonObject);
    log.debug("Json String {}", jsonString);
    assertion.getAttributeStatements().add(createAttributes());
    AssertionMarshaller marshaller = new AssertionMarshaller();
    Element plaintextElement = marshaller.marshall(assertion);
    String originalAssertionString = ElementSupport.getElementContentAsString(plaintextElement);
    log.debug("Assertion String with Code review changes suggested : " + originalAssertionString);
    signAssertion(plaintextElement);
    samlAssertion.assertion = ElementSupport.getElementContentAsString(plaintextElement);
    return samlAssertion;
  }
  
  private AttributeStatement createAttributes()
  {
    SAMLObjectBuilder attrStatementBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
    AttributeStatement attrStatement = (AttributeStatement)attrStatementBuilder.buildObject();
    attrStatement.getAttributes().add(createStringAttribute(key, jsonString));
    return attrStatement;
  }
  
  private Attribute createStringAttribute(String key, String value)
  {
    SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
    Attribute attr = (Attribute)attrBuilder.buildObject();
    attr.setName(key);
    log.debug(key);
    XMLObjectBuilder xmlBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
    XSString attrValue = (XSString)xmlBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
    attrValue.setValue(value);
    log.debug(value);
    attr.getAttributeValues().add(attrValue);
    return attr;
  }
  
  private Subject createSubject(String key, IssuerConfiguration issuerConfiguration)
    throws InitializationException, UnknownHostException
  {
    SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
    Subject subject = (Subject)subjectBuilder.buildObject();
    log.debug("Inside Create Subject");
    subject.setNameID(createNameID(key));
    log.debug("NameID was created successfully");
    subject.getSubjectConfirmations().add(createSubjectConfirmation(issuerConfiguration));
    return subject;
  }
  
  private NameID createNameID(String key)
  {
    SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
    NameID nameId = (NameID)nameIdBuilder.buildObject();
    nameId.setValue(key);
    log.debug("Inside createNameID {}", nameId.getValue());
    
    nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    return nameId;
  }
  
  private SubjectConfirmation createSubjectConfirmation(IssuerConfiguration issuerConfiguration)
    throws InitializationException, UnknownHostException
  {
    SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
    SubjectConfirmation subjectConfirmation = (SubjectConfirmation)subjectConfirmationBuilder.buildObject();
    subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");
    subjectConfirmation.setSubjectConfirmationData(createSubjectConfirmationData(issuerConfiguration));

    SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
    NameID nameId = (NameID)nameIdBuilder.buildObject();
    nameId.setValue(issuerConfiguration.getIssuerServiceName());
    log.debug("Inside createSubject Confirmation {}", nameId.getValue());
    nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    subjectConfirmation.setNameID(nameId);
    return subjectConfirmation;
  }
  
  private SubjectConfirmationData createSubjectConfirmationData(IssuerConfiguration issuerConfiguration)
    throws InitializationException, UnknownHostException
  {
    SAMLObjectBuilder confirmationMethodBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
    SubjectConfirmationData confirmationMethod = (SubjectConfirmationData)confirmationMethodBuilder.buildObject();
    DateTime now = new DateTime();
    samlAssertion.created_ts = now.toDate();
    if (samlAssertion != null) {
      log.debug("Created samlAssertion with TS {}", samlAssertion.created_ts);
    }
    confirmationMethod.setNotBefore(now);
    if (issuerConfiguration.getValiditySeconds() != null && samlAssertion != null)
    {
      confirmationMethod.setNotOnOrAfter(now.plusSeconds(issuerConfiguration.getValiditySeconds().intValue()));
      log.debug("IssuerConfiguration validity seconds not null {}", issuerConfiguration.getValiditySeconds());
      
      samlAssertion.expiry_ts = confirmationMethod.getNotOnOrAfter().toDate();
    }
    return confirmationMethod;
  }
  
  private void signAssertion(Element value)
    throws GeneralSecurityException, XMLSignatureException, MarshalException
  {
    signatureGenerator.signSAMLObject(value);
  }
}
