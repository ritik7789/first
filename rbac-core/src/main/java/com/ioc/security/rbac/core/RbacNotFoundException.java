package com.ioc.security.rbac.core;

/**
 * Raised when a referenced role, permission or assignment does not exist.
 */
public class RbacNotFoundException extends RbacException {

    public RbacNotFoundException(String message) {
        super(message);
    }
}
