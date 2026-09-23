package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.authority.RbacAuthorityMapper;
import com.ioc.security.rbac.spring.authority.RbacJwtAuthoritiesConverter;
import com.ioc.security.rbac.spring.subject.TenantResolver;
import com.ioc.security.rbac.spring.web.RbacUrlRules;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Beans the host application can plug into its {@code SecurityFilterChain}.
 */
@AutoConfiguration(after = RbacAutoConfiguration.class)
@ConditionalOnProperty(prefix = "rbac", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean(RbacService.class)
@ConditionalOnClass(HttpSecurity.class)
public class RbacWebSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public RbacUrlRules rbacUrlRules(RbacProperties properties, RbacService rbacService) {
        return new RbacUrlRules(properties.getUrlRules(), rbacService);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {
            "org.springframework.security.oauth2.jwt.Jwt",
            "org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter"})
    static class JwtConfiguration {

        @Bean
        @ConditionalOnMissingBean
        RbacJwtAuthoritiesConverter rbacJwtAuthoritiesConverter(RbacAuthorityMapper mapper, RbacProperties properties,
                                                                TenantResolver tenantResolver) {
            RbacProperties.MultiTenancy tenancy = properties.getMultiTenancy();
            return new RbacJwtAuthoritiesConverter(mapper, properties.getSubject().getClaim(),
                    tenancy.isEnabled() ? tenancy.getClaim() : null, tenantResolver);
        }
    }
}
