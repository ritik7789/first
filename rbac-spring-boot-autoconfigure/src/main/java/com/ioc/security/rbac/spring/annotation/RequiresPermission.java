package com.ioc.security.rbac.spring.annotation;

import com.ioc.security.rbac.spring.Logical;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the caller to hold the given permission(s). Can be placed on a class (applies to all its public methods)
 * and/or on methods; when both are present both requirements must be met.
 *
 * <pre>{@code
 * @RequiresPermission("booking:cancel")
 * @RequiresPermission(value = {"booking:read", "report:read"}, logical = Logical.ANY)
 * }</pre>
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequiresPermission {

    /** Required permission codes, e.g. {@code booking:cancel}. */
    String[] value();

    /** Whether all or any of the permissions are required. */
    Logical logical() default Logical.ALL;
}
