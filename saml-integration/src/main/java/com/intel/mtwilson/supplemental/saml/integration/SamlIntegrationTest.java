/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */


package com.intel.mtwilson.supplemental.saml.integration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.intel.kunit.annotations.Integration;
import com.intel.mtwilson.supplemental.saml.SAML;
import com.intel.dcsg.cpg.configuration.MapConfiguration;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.mtwilson.supplemental.saml.IssuerConfiguration;
import com.intel.mtwilson.supplemental.saml.JsonFormatter;

import com.intel.mtwilson.supplemental.saml.SamlAssertion;
import java.io.IOException;
import java.net.URLDecoder;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import org.apache.commons.lang3.StringEscapeUtils;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;

import com.intel.mtwilson.supplemental.saml.MapFormatter;
import com.intel.mtwilson.supplemental.saml.XMLFormatter;

/**
 *
 * @author srege
 */
public class SamlIntegrationTest {
    private SamlAssertion testMapSamlAssertion,testJsonSamlAssertion,testXMLSamlAssertion;
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlIntegrationTest.class);

   @Integration
    public SamlAssertion generateMapAssertion(String hostAttributes) throws InitializationException, NoSuchAlgorithmException, CryptographyException, IOException, MarshallingException, GeneralSecurityException, XMLSignatureException, MarshalException{
        
        HashMap<String, String> settings = new HashMap<>();
        settings.put("saml.issuer", "http://1.2.3.4/AttestationService");
        settings.put("saml.keystore.file", "/SAML.jks");
        settings.put("saml.validity.seconds", "3600");
        settings.put("saml.keystore.password", "password");
        settings.put("saml.key.alias", "forSigning");
        settings.put("saml.key.password", "password");
        settings.put("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        MapConfiguration configuration = new MapConfiguration(settings);
        KeyPair keypair = RsaUtil.generateRsaKeyPair(2048);
        X509Certificate certificate = RsaUtil.generateX509Certificate("CN=test", keypair, 1);
        ObjectMapper mapper = new ObjectMapper();
      
        IssuerConfiguration testIssuer = new IssuerConfiguration(keypair.getPrivate(), certificate, configuration,"","CIT Next Gen",3600);
        SAML testMapSaml = new SAML(testIssuer);
        String mapInput = URLDecoder.decode(hostAttributes, "UTF-8");
        Map<String, String> testmap = new HashMap<String, String>();
        testmap = mapper.readValue(mapInput, new TypeReference<Map<String, String>>(){});
        MapFormatter mapFormatter  = new MapFormatter(testmap);
        testMapSamlAssertion = testMapSaml.generateSamlAssertion(mapFormatter);
         
        testMapSamlAssertion.assertion = StringEscapeUtils.unescapeJava(testMapSamlAssertion.assertion);
        return testMapSamlAssertion;
    }
    
    @Integration
    public SamlAssertion generateJSONAssertion(String key , String hostAttributes) throws InitializationException, NoSuchAlgorithmException, CryptographyException, IOException, MarshallingException, GeneralSecurityException, XMLSignatureException, MarshalException{
        HashMap<String, String> settings = new HashMap<>();
        settings.put("saml.issuer", "http://1.2.3.4/AttestationService");
        settings.put("saml.keystore.file", "/SAML.jks");
        settings.put("saml.validity.seconds", "3600");
        settings.put("saml.keystore.password", "password");
        settings.put("saml.key.alias", "forSigning");
        settings.put("saml.key.password", "password");
        settings.put("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        MapConfiguration configuration = new MapConfiguration(settings);
        KeyPair keypair = RsaUtil.generateRsaKeyPair(2048);
        X509Certificate certificate = RsaUtil.generateX509Certificate("CN=test", keypair, 1);
        
      
        IssuerConfiguration testIssuer = new IssuerConfiguration(keypair.getPrivate(), certificate, configuration,"","CIT Next Gen",3600);
        SAML testJsonSaml = new SAML(testIssuer);
        String jsonInput = URLDecoder.decode(hostAttributes, "UTF-8");
        String keyInput = URLDecoder.decode(key, "UTF-8");
        
       JsonParser parser = new JsonParser();
       
         JsonObject testJSON = parser.parse(jsonInput).getAsJsonObject();
        JsonFormatter jsonFormatter = new JsonFormatter(keyInput,testJSON);
        testJsonSamlAssertion = testJsonSaml.generateSamlAssertion(jsonFormatter);
        testJsonSamlAssertion.assertion = StringEscapeUtils.unescapeJava(testJsonSamlAssertion.assertion);
        return testJsonSamlAssertion;
        
    }
 
    @Integration
    public SamlAssertion generateXMLAssertion(String key , String hostAttributes) throws InitializationException, NoSuchAlgorithmException, CryptographyException, IOException, MarshallingException, GeneralSecurityException, XMLSignatureException, MarshalException{
        HashMap<String, String> settings = new HashMap<>();
        settings.put("saml.issuer", "http://1.2.3.4/AttestationService");
        settings.put("saml.keystore.file", "/SAML.jks");
        settings.put("saml.validity.seconds", "3600");
        settings.put("saml.keystore.password", "password");
        settings.put("saml.key.alias", "forSigning");
        settings.put("saml.key.password", "password");
        settings.put("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        MapConfiguration configuration = new MapConfiguration(settings);
        KeyPair keypair = RsaUtil.generateRsaKeyPair(2048);
        X509Certificate certificate = RsaUtil.generateX509Certificate("CN=test", keypair, 1);
       
        String xmltest = URLDecoder.decode(hostAttributes, "UTF-8");
          String keyInput = URLDecoder.decode(key, "UTF-8");
        IssuerConfiguration testIssuer = new IssuerConfiguration(keypair.getPrivate(), certificate, configuration,"","CIT Next Gen",3600);
        SAML testXMLSaml = new SAML(testIssuer);
       
        
        XMLFormatter xmlFormatter = new XMLFormatter(keyInput,xmltest);
        testXMLSamlAssertion = testXMLSaml.generateSamlAssertion(xmlFormatter);
        testXMLSamlAssertion.assertion = StringEscapeUtils.unescapeJava(testXMLSamlAssertion.assertion);
        return testXMLSamlAssertion;
        
    }
}
