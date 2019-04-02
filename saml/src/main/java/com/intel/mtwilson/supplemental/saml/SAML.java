/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

import java.security.GeneralSecurityException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.io.MarshallingException;

/**
 * SAML library provides a library utility to generate an XML SAML report. It
 * generates attestation reports for host or VM attestation status in SAML
 * format.
 *
 * @author srege
 */
public class SAML {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SAML.class);

    private Assertion assertion;
    public final IssuerConfiguration issuerConfiguration;
    private final Integer validitySeconds; // for example 3600 for one hour

    private SamlAssertion samlAssertion;
    private final XMLObjectBuilderFactory builderFactory;

    
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

    public SAML(IssuerConfiguration issuerConfiguration) throws InitializationException {
        this.issuerConfiguration = issuerConfiguration;
        this.validitySeconds = issuerConfiguration.getValiditySeconds();
        this.builderFactory = XMLObjectBuilderFactoryHolder.builderFactory;

        log.debug("IssuerConfiguration validitySeconds: {}", this.validitySeconds);
        assert validitySeconds != null;

    }

    /**
     * * This method accepts multiple input types for creating various forms of
     * assertions like HostAssertion , VMAssertion, HostWithTagAssertion
     *
     * @param formatters AssertionFormatter
     * @return samlAssertion
     *
     */
    public SamlAssertion generateSamlAssertion(AssertionFormatter... formatters) throws MarshallingException, GeneralSecurityException, XMLSignatureException, MarshalException {

        log.debug("Received request to create assertion");
        for (AssertionFormatter i : formatters) {
            samlAssertion = i.generateAssertion(issuerConfiguration, assertion);

        }
        return samlAssertion;

    }

    /**
     * Signs the Saml Assertion and returns the signed assertion
     *
     */
}
