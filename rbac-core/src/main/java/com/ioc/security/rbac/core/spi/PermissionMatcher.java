package com.ioc.security.rbac.core.spi;

/**
 * Decides whether a granted permission (possibly containing wildcards) implies a required permission.
 */
@FunctionalInterface
public interface PermissionMatcher {

    boolean implies(String granted, String required);
}
