/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

import com.intel.dcsg.cpg.configuration.Configuration;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Loads the private key, certificate, and other settings required for the SAML
 * issuer.
 *
 * @author jbuhacoff 
 * @author srege
 */

public class IssuerConfiguration {
    private final PrivateKey privateKey;
    private final Certificate certificate;
    private final String issuerName; 
    private final String issuerServiceName; 
    private final String jsr105provider;
    private final Integer validitySeconds;

    public IssuerConfiguration(PrivateKey privateKey, Certificate certificate, Configuration configuration, String issuerName,String issuerServiceName,Integer validitySeconds) {
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.issuerName = issuerName;
        this.issuerServiceName = issuerServiceName;
        jsr105provider = "org.jcp.xml.dsig.internal.dom.XMLDSigRI";
        this.validitySeconds = validitySeconds;
    }
  public IssuerConfiguration(PrivateKey privateKey, Certificate certificate, Configuration configuration, String issuerName,String issuerServiceName,Integer validitySeconds,String jsr105provider ) {
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.issuerName = issuerName;
        this.issuerServiceName = issuerServiceName;
        this.jsr105provider = jsr105provider;
        this.validitySeconds = validitySeconds;
    }
   

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public String getIssuerServiceName() {
        return issuerServiceName;
    }

    public String getJsr105Provider() {
        return jsr105provider;
    }

    public Integer getValiditySeconds() {
        return validitySeconds;
    }

    /**
     * Get a KeyStore object given the keystore filename and password.
     */
    
}
