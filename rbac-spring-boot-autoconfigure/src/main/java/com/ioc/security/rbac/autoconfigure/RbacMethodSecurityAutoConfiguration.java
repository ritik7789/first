package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.annotation.RbacAnnotationPointcut;
import com.ioc.security.rbac.spring.annotation.RbacMethodInterceptor;
import org.springframework.aop.Advisor;
import org.springframework.aop.config.AopConfigUtils;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.context.annotation.Role;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;

import java.io.Serializable;

/**
 * Enforces {@code @RequiresPermission} / {@code @RequiresRole} through a Spring AOP advisor. Works without
 * {@code @EnableMethodSecurity} and without AspectJ.
 */
@AutoConfiguration(after = RbacAutoConfiguration.class)
@ConditionalOnProperty(prefix = "rbac", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean(RbacService.class)
@Import(RbacMethodSecurityAutoConfiguration.AutoProxyRegistrar.class)
public class RbacMethodSecurityAutoConfiguration {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnProperty(prefix = "rbac.method-security", name = "enabled", havingValue = "true",
            matchIfMissing = true)
    static Advisor rbacMethodSecurityAdvisor(ObjectProvider<RbacService> rbacService, Environment environment) {
        DefaultPointcutAdvisor advisor = new DefaultPointcutAdvisor(new RbacAnnotationPointcut(),
                new RbacMethodInterceptor(rbacService));
        advisor.setOrder(environment.getProperty("rbac.method-security.order", Integer.class, 100));
        return advisor;
    }

    /**
     * Spring Security does not pick up a {@link PermissionEvaluator} bean on its own, so {@code hasPermission(...)}
     * expressions would always be denied. Provide an expression handler wired to it, unless the application defines
     * its own handler.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(DefaultMethodSecurityExpressionHandler.class)
    static class ExpressionHandlerConfiguration {

        @Bean
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        @ConditionalOnMissingBean(MethodSecurityExpressionHandler.class)
        static MethodSecurityExpressionHandler rbacMethodSecurityExpressionHandler(
                ObjectProvider<PermissionEvaluator> permissionEvaluator,
                ObjectProvider<GrantedAuthorityDefaults> authorityDefaults,
                ObjectProvider<RoleHierarchy> roleHierarchy) {
            DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
            handler.setPermissionEvaluator(new LazyPermissionEvaluator(permissionEvaluator));
            authorityDefaults.ifAvailable(d -> handler.setDefaultRolePrefix(d.getRolePrefix()));
            roleHierarchy.ifAvailable(handler::setRoleHierarchy);
            return handler;
        }
    }

    private record LazyPermissionEvaluator(ObjectProvider<PermissionEvaluator> delegate) implements PermissionEvaluator {

        @Override
        public boolean hasPermission(Authentication authentication, Object target, Object permission) {
            PermissionEvaluator evaluator = delegate.getIfAvailable();
            return evaluator != null && evaluator.hasPermission(authentication, target, permission);
        }

        @Override
        public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
                                     Object permission) {
            PermissionEvaluator evaluator = delegate.getIfAvailable();
            return evaluator != null && evaluator.hasPermission(authentication, targetId, targetType, permission);
        }
    }

    /**
     * Makes sure an infrastructure auto-proxy creator exists (it is a no-op when Spring Boot's AOP support or
     * Spring Security method security already registered a more capable one).
     */
    static class AutoProxyRegistrar implements ImportBeanDefinitionRegistrar {

        @Override
        public void registerBeanDefinitions(AnnotationMetadata metadata, BeanDefinitionRegistry registry) {
            AopConfigUtils.registerAutoProxyCreatorIfNecessary(registry);
            AopConfigUtils.forceAutoProxyCreatorToUseClassProxying(registry);
        }
    }
}
