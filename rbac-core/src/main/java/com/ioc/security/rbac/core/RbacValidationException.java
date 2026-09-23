package com.ioc.security.rbac.core;

/**
 * Raised when input (a permission code, role name, hierarchy change, ...) is invalid.
 */
public class RbacValidationException extends RbacException {

    public RbacValidationException(String message) {
        super(message);
    }
}
