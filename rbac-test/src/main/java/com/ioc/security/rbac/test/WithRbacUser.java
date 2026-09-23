package com.ioc.security.rbac.test;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Runs a test as an authenticated subject with the given RBAC roles and/or permissions, without touching the RBAC
 * store. Roles are expanded with the real role definitions (parents and permissions) when they exist in the store.
 *
 * <pre>{@code
 * @Test
 * @WithRbacUser(permissions = "booking:cancel")
 * void agentCanCancel() { ... }
 *
 * @Test
 * @WithRbacUser(value = "alice", roles = "OPS_MANAGER")
 * void managerCanReschedule() { ... }
 * }</pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithRbacUserSecurityContextFactory.class)
public @interface WithRbacUser {

    /** Subject id (also used as the authentication name). */
    String value() default "user";

    /** RBAC roles granted to the subject. */
    String[] roles() default {};

    /** Permissions granted to the subject in addition to those of {@link #roles()}. */
    String[] permissions() default {};
}
