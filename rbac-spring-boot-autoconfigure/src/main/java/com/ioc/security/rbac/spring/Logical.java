package com.ioc.security.rbac.spring;

/**
 * How several required permissions or roles are combined.
 */
public enum Logical {
    /** Every listed permission / role is required. */
    ALL,
    /** At least one listed permission / role is required. */
    ANY
}
