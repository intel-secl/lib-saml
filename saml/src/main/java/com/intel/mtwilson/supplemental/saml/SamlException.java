/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.supplemental.saml;

/**
 * Typically wraps MarshallingException, ConfigurationException, 
 * UnknownHostException, GeneralSecurityException, XMLSignatureException, 
 * or MarshalException 
 * 
 * @author jbuhacoff
 */
public class SamlException extends Exception {
    public SamlException() {
        super();
    }
    public SamlException(Throwable cause) {
        super(cause);
    }
    public SamlException(String message) {
        super(message);
    }
    public SamlException(String message, Throwable cause) {
        super(message, cause);
    }    
}
