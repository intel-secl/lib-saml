/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.MapConfiguration;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
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
    
    @Test
    public void trustAssertion() throws CryptographyException {
        String saml = "<saml2:Assertion ID=\"MapAssertion\" IssueInstant=\"2020-08-12T22:21:29.287Z\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:Issuer>AttestationService</saml2:Issuer><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#MapAssertion\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>gLQQSU+/EQVIANMlB3S/hMRXYu3g4qPpwRzjhoYe4pY=</DigestValue></Reference></SignedInfo><SignatureValue>MqCG3B3ZLU2eXUebFFib7WRmHiVeHYN/PUJsvqx/Y+tZFNdMqrgTL2trvPAc7kGhW6AIqLZjVZOBPMmPhJZMT6FkpEarQarKOMo/MrFwYCXOvRuGeIcYy+GjlMkQr4FQaUhDi7zhSb1wU4drTHVfj0oMhsarLMnYLYXF3UpE2bR/xu2uwvy3u4UlsFSmWahWu9RBd7LvHmnHmAHYMk2IoDZRPI0DFdprXq5e3wVQwaah9lOESfFJzHZPKHo94f4a8Gpwrg2Trh/aVxEtoqZbnzEpdV60cJt+mikyOFNrEE25ZWFMBjsROo1sNZBa9d4h8ui8tZ7UDpBNy44cSOVU38Z6z2r+uel8OuzMJ2yYxIVgQqcnEBwG9IoKAPkm3pJMfUXmrN5Um6S5PzEvEiQgWK0yXH7wxch+B9hMZazS5KPK+x8Y8TirtUN7w8DSXUEg1+ZTAOLmWIAnrowoiObjwwyTNWLhpndwkCuzRfqyMMz6BwXEcNbQW8nnbkQLVIm5</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID/DCCAmSgAwIBAgIBHjANBgkqhkiG9w0BAQwFADBQMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwHhcNMjAwODEyMjIxNzEwWhcNMjEwODEyMjIxNzEwWjAfMR0wGwYDVQQDExRIVlMgU0FNTCBDZXJ0aWZpY2F0ZTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALAgTlPcy93Z/IrrhlMLcNXMe+/ewNO4NvkqLQDrWNWtIBxRpokGHyd0/L04QUKKM7TA5JGP3c17p/RcVR51TC3agtJZh5BPMWdygF5pg4Tw5VQDEIX3j8HaBP1rFZGILhjWbNhMGTT7u/DkZfW9a82u+k2tcYO4AeaQmk05wMnWUMsLz4IOWUVLZvvMDWik4WhKhm4kGVMkA0SldKhCWgFZO+9FmURQ+8XzCyTA8dMqfG+2vaViPrO3mVKQXCom74veiovMsnPp+qklmieSkhMfB/spwPj/IcVW8bg3BJ2D+o4xgi0soe/NaZWxs/HmR8Nxj/q9io3f0VSiqAr4QoE3VOyRJ6yp4+7eYxzbP2KfC4pVR3xLAZQm2B5zz7c/eVgAlmf0lpfY3iIrIrgCnnLlIBy5iwZMZDBWDklafFbjR8uxs6w2ndY6ujF1qHvbnpTxGIURp41F8wDA19cZfbmV/XWXOWjBkOV1Mlr3KPkBKUewE9vsnsIE1XdSawuWRQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQEMBQADggGBAC8z9Tlfh9EBd0xVicf4Nu7zQesUTynbQV0U0jxY/iatHvCmCb3JkP3eHZ1AFstQYk162a64RXLGIAepo0gQ7W/5S3aHvOzJ8oAOTAT8zIRhWUyBFN/yM8n3H+7/ec+CP8rTJQ9b2JFVY84YyKg+dnpNuJFk+UzvC9xeETMkFJ6tru9ZCWAk95qACSnQ4oVsyzxC3+k8Ew2Gc9dBn3C3k625MeXmEgXckYv8lh57tDAWr53Wx3caTQS0zFrZgT9JHW1iH4XpR+xkbAyulu/kiSPZ4KLnrCAqaSxHwcxpw6ATWvFOFcA9hllm3fYFA0+s59M6dzBwlj45uqEaB2B9vqF9KUiFejkvd5m2sK5jQhy9ZsUeEqmeU/Urb1PcSxBlJn6m6GgxkLUYgT5lqlzuzNHMGMicmxa+mPnKZiyJLMxGEs1CV0dQSatVAPRIsyj99aCKxQ+RSNyqCuFLxJ0KJqRjK8lA5Anfrdv1WeH70pkltuOwTpwYpl1KlRLK7M3fiw==</X509Certificate></X509Data></KeyInfo></Signature><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">HVS</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches\"><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"/><saml2:SubjectConfirmationData NotBefore=\"2020-08-12T22:21:29.287Z\" NotOnOrAfter=\"2020-08-13T22:21:29.287Z\"/></saml2:SubjectConfirmation></saml2:Subject><saml2:AttributeStatement><saml2:Attribute Name=\"VMMVersion\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">19.03.5</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"HostName\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">Q15RU4.fm.intel.com</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"HardwareUUID\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">00462919-8127-e711-906e-0017a4403562</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"BiosVersion\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">SE5C620.86B.00.01.0015.110720180833</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"NumberOfSockets\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">2</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"ProcessorInfo\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">54 06 05 00 FF FB EB BF</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"VMMName\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">Docker</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"OSVersion\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">8.2</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TRUST_SOFTWARE\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"FEATURE_TPM\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"FEATURE_TXT\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TRUST_ASSET_TAG\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">NA</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TRUST_PLATFORM\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TRUST_OS\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"Binding_Key_Certificate\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">MIIFHDCCA4SgAwIBAgIRA0kqCGWrZawJvHKpakZCDI8wDQYJKoZIhvcNAQEMBQAwIjEgMB4GA1UEAxMXSFZTIFByaXZhY3kgQ2VydGlmaWNhdGUwHhcNMjAwODExMTcxMzMxWhcNMzAwODExMTcxMzMxWjAiMSAwHgYDVQQDDBdCaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASEwDQYJKoZIhvcNAQEBBQADggEOADCCAQkCggEBAJJj4/8IZHwvsc3C/u3HXRQY+EG6Ua8G22D1EmnYNyb9CdKk26Cu5e7OqAyCcHMPRUT8PV19BgxSKhX/3fsVUF2uPOQdW17cQ+laxqp12/y6TsWI+nXlT2c1gfzrdMdWVCLpv11ND3e/XxKSJWqOyUxHXxJZechvEZ61d2wqwk46c5tNwiCpzfrUomwBunKppJF36rJSCUZXGYRsufGJZLB8P/ftB45VJxVSlSgc9xHxZonYc5xa6yeek094hNaBr3l6p9I6CBrP/DlpOYn87CfyTzwKb9jvtiuFjv6eK3pOK1cNnmRiImWKyNqeLViV7OYbS2Z5an4moPB/51AaChcCAgEAo4IBzDCCAcgwDgYDVR0PAQH/BAQDAgWgMIGdBgdVBIEFAwIpBIGR/1RDR4AXACIACwXgPyaYsJWvnPdoRWpp3CVvd61LotrBsfB1y0cjdgA0AAQA/1WqAAAAAAACnvcAAAAGAAAAAQAABwAoAAgyAAAiAAu/fXFF2LoCbGAUiKnjviWCK+CVbHvLVn7Z95zpt/VaJgAiAAtAqfP2Kngea8ThnJ4AqTvv9f8w5Jhp8ZMAbfO2WZBbmDCCARQGCFUEgQUDAikBBIIBBgAUAAsBACwMxt/u+wyxrk2pufC/R47ajFOhX8tIMf2RTbyFahqJZafxb1dJdtUhDllIErVQ8DirObFVKaUist8qiDLcT2PRmLgFaKnHNNwpaZpEgWJ3KMWBUmXV4e197/vBQp1chIN9rMo1v8E8x8EjDHVIIxaSYjY36IHCUfqAIsxqlVj9Mssa+vOMmMju60opZEFQuDYenr+jcWBuTwjYjs5jrdOhljkrbZj35zu5g5+uzo94Ejrgv/aX6iL5Qhkbfe6sEPpx8r9q1TfjBQopy3x+T+FR9VJ9Yenx/WSZ+0BpBRCHTn5tQgFK81/qdvE5RWi22LgMX6P9e0O1tvfsARoKVJEwDQYJKoZIhvcNAQEMBQADggGBAFj+btHP9VOh6zSlPyMFH1YPqoReeX+ayMiCnecGs8q7IKcmb5vh/O4af5VuW2w3dprBz1j+WHC/CeUvmDnF3lJJPsrSzJy48Im7yh75/MvtTT5SGI6tNrvfJ0QAPijqPZu+8LQOoj2FoLE5mu2Wqo3dIrTJYW05r3Qi3czz1cVDG9nixR+eabtRNml9k/aJApVhBEM9zHua7MqMgYw72XTE411BsFva68H7lmn/xplyY8HK928VH6Zzamel2fV29KMIgiAqn+/zN1c/baOZzhNxTCSG88XICMtlY5QiVx7bCU0IJyLy82YCXYkHV7IJ+D2zbIwK7BHW8Id7zLCcu3QaAtNsjJf5mn2YvYNQ+4log24gQIdlSGWcedq7XxLSER7A6YL4NTJxBMQa1vZIhVG3lQx4CUmGCyceHyeRcqt9Xx5JBEZxA6efdoZljavzaTxgp7Hyc5J4wn1OBK894c/ali3VznuOclsFXKBQjdBsOgmMryl2i76CIQqCjAA+CQ==</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"ProcessorFlags\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TbootInstalled\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"IsDockerEnvironment\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">false</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TRUST_OVERALL\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"BiosName\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">Intel Corporation</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"InstalledComponents\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">[tagent wlagent]</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TPMVersion\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">2.0</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"TRUST_HOST_UNIQUE\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"AIK_Certificate\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">MIIDUTCCAbmgAwIBAgIRAKTA+fsqb2KWTZFIVgoXs4UwDQYJKoZIhvcNAQELBQAwIjEgMB4GA1UEAxMXSFZTIFByaXZhY3kgQ2VydGlmaWNhdGUwHhcNMjAwODEyMjIxODI5WhcNMjUwODEyMjIxODI5WjAiMSAwHgYDVQQDExdIVlMgUHJpdmFjeSBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJb3jZkZf3v7Jx2aM0Lo1RNsYRqh82yMS6/9RQPzQuI23je2nDwJ7NWfKub8UExs613jldVbN9rNEx7VTeJhAmfcLDr5lP/4dVFsKYmytkZoJutKsGLF4+tW0pXdJ9jqfjkpEZS2WgYX0pr13iQu6S5GLyKHL/m6PkAFMFcrOjSq+zVcRBpiBgF+Tb3mz0wQoHo2JYd9B563Mtp+bCnGMjl6fy5GSVy0WpBh3O150obp2r8AI+12XbYsZXVyRUYXQpNpPms/Onn/UzQiDvgGjj3apiCTppe1l3wyEHE46nWfDVmdxENM5t6cceuBhSTa1zbMcz6xtc7RDpw9mWloBuUCAwEAAaMCMAAwDQYJKoZIhvcNAQELBQADggGBAEhu92dSDuCAaVw7zu9iIhe6YS1UQrt68xpkPHbCHirubJd4bnLkfKPTP0lF/UJMqd4XybCDirOEFc+vs5HR0SSzVxX0g73nZzyZSkVV+8WmibDzyy/oX35o2L2rW0KDkWf4lQE8JDLyksY4p9vqlJcKQi/os0K/cbRbROMtvAN0vuW073TXskHEVLeYYOSimX154v9xl6UN62kWgomQazlkP9b5b0bR24hM4YpwW/1OCg3Pc/IyzNVF5ionspansjprizvjtlgga9zJhmaMP6+OtK38N8kEwMT8fy77zasJC4M1+4DUV5dcWABAvkL/qVdqf2xWotNKBM/THDjevvCJ+lNoxftEY69+UZ4KN1GAqYxG5Gdg1rcenN/tQuDVeEj3wobWCP8CSkApvgTBwlZfl0jx/0HkIuKvVLYvgtMdamuX2lnnNkAngAMxsxwWAYmIY3XoHBK6UqONugFNa8gMk3/beliIgmpA3uuJYFEDLEEOANXkaHBLHSmMLG17iA==</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name=\"OSName\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">RedHatEnterprise</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>";
        String certificateString = "MIID/DCCAmSgAwIBAgIBHjANBgkqhkiG9w0BAQwFADBQMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwHhcNMjAwODEyMjIxNzEwWhcNMjEwODEyMjIxNzEwWjAfMR0wGwYDVQQDExRIVlMgU0FNTCBDZXJ0aWZpY2F0ZTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALAgTlPcy93Z/IrrhlMLcNXMe+/ewNO4NvkqLQDrWNWtIBxRpokGHyd0/L04QUKKM7TA5JGP3c17p/RcVR51TC3agtJZh5BPMWdygF5pg4Tw5VQDEIX3j8HaBP1rFZGILhjWbNhMGTT7u/DkZfW9a82u+k2tcYO4AeaQmk05wMnWUMsLz4IOWUVLZvvMDWik4WhKhm4kGVMkA0SldKhCWgFZO+9FmURQ+8XzCyTA8dMqfG+2vaViPrO3mVKQXCom74veiovMsnPp+qklmieSkhMfB/spwPj/IcVW8bg3BJ2D+o4xgi0soe/NaZWxs/HmR8Nxj/q9io3f0VSiqAr4QoE3VOyRJ6yp4+7eYxzbP2KfC4pVR3xLAZQm2B5zz7c/eVgAlmf0lpfY3iIrIrgCnnLlIBy5iwZMZDBWDklafFbjR8uxs6w2ndY6ujF1qHvbnpTxGIURp41F8wDA19cZfbmV/XWXOWjBkOV1Mlr3KPkBKUewE9vsnsIE1XdSawuWRQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQEMBQADggGBAC8z9Tlfh9EBd0xVicf4Nu7zQesUTynbQV0U0jxY/iatHvCmCb3JkP3eHZ1AFstQYk162a64RXLGIAepo0gQ7W/5S3aHvOzJ8oAOTAT8zIRhWUyBFN/yM8n3H+7/ec+CP8rTJQ9b2JFVY84YyKg+dnpNuJFk+UzvC9xeETMkFJ6tru9ZCWAk95qACSnQ4oVsyzxC3+k8Ew2Gc9dBn3C3k625MeXmEgXckYv8lh57tDAWr53Wx3caTQS0zFrZgT9JHW1iH4XpR+xkbAyulu/kiSPZ4KLnrCAqaSxHwcxpw6ATWvFOFcA9hllm3fYFA0+s59M6dzBwlj45uqEaB2B9vqF9KUiFejkvd5m2sK5jQhy9ZsUeEqmeU/Urb1PcSxBlJn6m6GgxkLUYgT5lqlzuzNHMGMicmxa+mPnKZiyJLMxGEs1CV0dQSatVAPRIsyj99aCKxQ+RSNyqCuFLxJ0KJqRjK8lA5Anfrdv1WeH70pkltuOwTpwYpl1KlRLK7M3fiw==";
        byte[] certificateData = Base64.getDecoder().decode(certificateString);
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X509");
            certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            X509Certificate[] trustedSigners = new X509Certificate[]{certificate};
            TrustAssertion ta = new TrustAssertion(trustedSigners, saml);
            com.intel.mtwilson.supplemental.saml.TrustAssertion.HostTrustAssertion hostTrustAssertion = ta.getTrustAssertion("Q15RU4.fm.intel.com");

            for (String attr : hostTrustAssertion.getAttributeNames()) {
                System.out.println("hta : " + attr);
            }

            System.out.println("testing..... : " + hostTrustAssertion.getSubjectFormat());
            if (hostTrustAssertion.getAikCertificate() == null) {
                System.out.println("aik cert empty");
            } else {
                System.out.println("aik cert not empty");
            }
            if (hostTrustAssertion.getBindingKeyCertificate() == null) {
                System.out.println(" bk cert empty");
            } else {
                System.out.println(" bk cert not empty");
            }
           System.out.println("OS name is "+hostTrustAssertion.getVMMOSName());
           System.out.println("TPM version is "+hostTrustAssertion.getTPMVersion());
           PublicKey aikPublicKey = hostTrustAssertion.getAikPublicKey();
           System.out.println("aik pub key : "+ aikPublicKey.toString());
            
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }
}
