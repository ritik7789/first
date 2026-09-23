package com.ioc.security.rbac.core;

/**
 * Base type for all errors raised by the RBAC library.
 */
public class RbacException extends RuntimeException {

    public RbacException(String message) {
        super(message);
    }

    public RbacException(String message, Throwable cause) {
        super(message, cause);
    }
}
