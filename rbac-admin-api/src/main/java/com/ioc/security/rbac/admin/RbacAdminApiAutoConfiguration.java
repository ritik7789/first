package com.ioc.security.rbac.admin;

import com.ioc.security.rbac.autoconfigure.RbacAutoConfiguration;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.spring.RbacService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Registers the admin REST API when {@code rbac.admin-api.enabled=true} in a servlet web application with a
 * writable RBAC store.
 */
@AutoConfiguration(after = RbacAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "rbac.admin-api", name = "enabled", havingValue = "true")
@ConditionalOnBean({RbacAdministration.class, RbacService.class})
@EnableConfigurationProperties(RbacAdminApiProperties.class)
public class RbacAdminApiAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public RbacAdminGuard rbacAdminGuard(RbacService rbacService, RbacAdministration administration,
                                         RbacAdminApiProperties properties) {
        return new RbacAdminGuard(rbacService, administration, properties);
    }

    @Bean
    public RbacAdminController rbacAdminController(RbacAdministration administration, RbacService rbacService,
                                                   RbacAdminGuard guard) {
        return new RbacAdminController(administration, rbacService, guard);
    }

    @Bean
    public RbacAdminExceptionHandler rbacAdminExceptionHandler() {
        return new RbacAdminExceptionHandler();
    }
}
