/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

import java.security.GeneralSecurityException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.core.xml.io.MarshallingException;

/**
 * Interface implemented by all Formatter classes to generate assertion for the specific input provided to them
 * @author srege
 *  
 */
public interface AssertionFormatter {
    public SamlAssertion generateAssertion(IssuerConfiguration issuerConfiguration,Assertion assertion) throws MarshallingException, GeneralSecurityException, XMLSignatureException, MarshalException;
}
