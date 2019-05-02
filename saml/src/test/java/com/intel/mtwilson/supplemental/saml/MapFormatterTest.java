/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.MapConfiguration;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Statement;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSString;
import static org.junit.Assert.assertNotNull;
import org.opensaml.core.xml.io.MarshallingException;

/**
 *
 * @author srege
 */
public class MapFormatterTest {

    public Map<String, String> inputMap;
    public Map<String, String> attributeMap;
    public Assertion assertion;
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MapFormatterTest.class);

    private void createInputData() throws IOException {
        inputMap = new HashMap();
        ObjectMapper mapper = new ObjectMapper();
        // String json = "{\"Location\":null,\"HostName\":\"192.168.30.154\",\"Port\":null,\"BIOS_Name\":\"Intel_VMware\",
        // \"BIOS_Version\":\"s60\",\"BIOS_Oem\":\"Intel Corporation\",\"VMM_Name\":\"ESXi\",\"VMM_Version\":\"5.1-12345\",
        // \"VMM_OSName\":\"VMware_ESXi\",\"VMM_OSVersion\":\"5.1.0\",\"IPAddress\":\"192.168.30.154\",
        // \"AddOn_Connection_String\":\"https://192.168.30.87:443/sdk;Administrator;P@ssw0rd\",
        // \"Description\":\"Test\",\"Email\":\"\"}";
        inputMap.put("hostName", "192.168.30.254");
        inputMap.put("BIOS_Name","Intel_VMware");
        inputMap.put("BIOS_OEM","Intel_Corpotation");
        log.debug("Created Input for Map");

    }

    public void getAttributeValues() {
        attributeMap = new HashMap();
        for (Statement statement : assertion.getStatements()) {
            if (statement instanceof AttributeStatement) {
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
                    log.debug("Attribute name {} = {} ", attribute.getName(), attributeValue);
                }

            }
        }
    }

    @Test
    public void testapplyToMapFormatter() throws NoSuchAlgorithmException, CryptographyException, IOException, MarshallingException, GeneralSecurityException, XMLSignatureException, MarshalException  {
        HashMap<String, String> settings = new HashMap<>();
        settings.put("saml.issuer", "http://1.2.3.4/AttestationService");
        settings.put("saml.keystore.file", "/SAML.p12");
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
        SamlAssertion testSamlAssertion = new SamlAssertion();
        log.debug("Entered the test method");
        try {
            createInputData();
        } catch (IOException ex) {
            Logger.getLogger(MapFormatterTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        log.debug("Calling MapFormatter class");
        MapFormatter testMapAssertionFormatter = new MapFormatter(inputMap);
        log.debug("HostName is {}",inputMap.get("hostName"));
        testSamlAssertion= testMapAssertionFormatter.generateAssertion(testIssuer,assertion);
        assertNotNull(testSamlAssertion);
    }
}
