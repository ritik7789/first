package com.ioc.security.rbac.spring.subject;

import org.springframework.security.core.Authentication;

/**
 * Determines the tenant the current request acts in. Return {@code null} when there is no tenant; then only global
 * role assignments apply.
 */
@FunctionalInterface
public interface TenantResolver {

    TenantResolver NONE = authentication -> null;

    String resolve(Authentication authentication);
}
