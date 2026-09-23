package com.ioc.security.rbac.core;

/**
 * Raised when an operation conflicts with existing data (duplicate, still referenced, ...).
 */
public class RbacConflictException extends RbacException {

    public RbacConflictException(String message) {
        super(message);
    }
}
