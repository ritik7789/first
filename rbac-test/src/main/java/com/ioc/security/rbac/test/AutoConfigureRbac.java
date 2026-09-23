package com.ioc.security.rbac.test;

import com.ioc.security.rbac.autoconfigure.RbacAutoConfiguration;
import com.ioc.security.rbac.autoconfigure.RbacMethodSecurityAutoConfiguration;
import com.ioc.security.rbac.autoconfigure.RbacStoreAutoConfiguration;
import com.ioc.security.rbac.autoconfigure.RbacWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Adds the RBAC auto-configuration (in-memory store unless another store is available) to test slices that do not
 * include it, e.g. {@code @DataJdbcTest} or a plain {@code @SpringJUnitConfig}. {@code @WebMvcTest} already includes it
 * when {@code rbac-test} is on the classpath.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@ImportAutoConfiguration({RbacStoreAutoConfiguration.class, RbacAutoConfiguration.class,
        RbacMethodSecurityAutoConfiguration.class, RbacWebSecurityAutoConfiguration.class,
        RbacTestAutoConfiguration.class})
public @interface AutoConfigureRbac {
}
