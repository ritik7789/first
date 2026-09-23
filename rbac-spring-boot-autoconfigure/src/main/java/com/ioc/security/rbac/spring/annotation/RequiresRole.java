package com.ioc.security.rbac.spring.annotation;

import com.ioc.security.rbac.spring.Logical;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the caller to hold the given RBAC role(s) (directly or through inheritance). Prefer
 * {@link RequiresPermission} so that roles can be re-shaped without code changes.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequiresRole {

    /** Required role names. */
    String[] value();

    /** Whether all or any of the roles are required. */
    Logical logical() default Logical.ALL;
}
