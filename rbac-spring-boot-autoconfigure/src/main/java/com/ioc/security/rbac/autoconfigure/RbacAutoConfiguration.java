package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.core.engine.AccessEvaluator;
import com.ioc.security.rbac.core.engine.CachingPermissionResolver;
import com.ioc.security.rbac.core.engine.HierarchicalPermissionResolver;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.engine.WildcardPermissionMatcher;
import com.ioc.security.rbac.core.spi.EvictablePermissionResolver;
import com.ioc.security.rbac.core.spi.PermissionMatcher;
import com.ioc.security.rbac.core.spi.PermissionResolver;
import com.ioc.security.rbac.core.spi.RbacChangeListener;
import com.ioc.security.rbac.core.spi.RbacManagementStore;
import com.ioc.security.rbac.core.spi.RbacStore;
import com.ioc.security.rbac.spring.RbacDecisionListener;
import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.authority.RbacAuthorityMapper;
import com.ioc.security.rbac.spring.event.ApplicationEventDecisionListener;
import com.ioc.security.rbac.spring.event.RbacAuditLogger;
import com.ioc.security.rbac.spring.event.SpringRbacChangeListener;
import com.ioc.security.rbac.spring.expression.RbacExpressions;
import com.ioc.security.rbac.spring.expression.RbacPermissionEvaluator;
import com.ioc.security.rbac.spring.seed.RbacSeedInitializer;
import com.ioc.security.rbac.spring.subject.DefaultSubjectIdResolver;
import com.ioc.security.rbac.spring.subject.DefaultTenantResolver;
import com.ioc.security.rbac.spring.subject.SubjectIdResolver;
import com.ioc.security.rbac.spring.subject.TenantResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.PermissionEvaluator;

import java.time.Clock;

/**
 * Core RBAC beans. Every bean backs off when the application defines its own bean of the same type.
 */
@AutoConfiguration(after = RbacStoreAutoConfiguration.class)
@ConditionalOnProperty(prefix = "rbac", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean(RbacStore.class)
@EnableConfigurationProperties(RbacProperties.class)
public class RbacAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PermissionMatcher rbacPermissionMatcher() {
        return new WildcardPermissionMatcher();
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionResolver rbacPermissionResolver(RbacStore store, RbacProperties properties) {
        PermissionResolver resolver = new HierarchicalPermissionResolver(store, Clock.systemUTC());
        RbacProperties.Cache cache = properties.getCache();
        if (cache.isEnabled()) {
            return new CachingPermissionResolver(resolver, cache.getTtl(), cache.getMaxEntries());
        }
        return resolver;
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessEvaluator rbacAccessEvaluator(PermissionMatcher matcher, RbacProperties properties) {
        return new AccessEvaluator(matcher, properties.getSuperAdminRole());
    }

    @Bean
    @ConditionalOnMissingBean
    public SubjectIdResolver rbacSubjectIdResolver(RbacProperties properties) {
        return new DefaultSubjectIdResolver(properties.getSubject().getClaim());
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantResolver rbacTenantResolver(RbacProperties properties) {
        RbacProperties.MultiTenancy tenancy = properties.getMultiTenancy();
        return tenancy.isEnabled() ? new DefaultTenantResolver(tenancy.getHeader(), tenancy.getClaim())
                : TenantResolver.NONE;
    }

    @Bean
    @ConditionalOnProperty(prefix = "rbac.audit", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ApplicationEventDecisionListener rbacApplicationEventDecisionListener(ApplicationEventPublisher publisher,
                                                                                RbacProperties properties) {
        return new ApplicationEventDecisionListener(publisher, properties.getAudit().isLogGranted());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rbac.audit", name = "enabled", havingValue = "true", matchIfMissing = true)
    public RbacAuditLogger rbacAuditLogger() {
        return new RbacAuditLogger();
    }

    @Bean
    @ConditionalOnMissingBean
    public RbacService rbacService(PermissionResolver resolver, AccessEvaluator evaluator,
                                   SubjectIdResolver subjectIdResolver, TenantResolver tenantResolver,
                                   ObjectProvider<RbacDecisionListener> listeners) {
        return new RbacService(resolver, evaluator, subjectIdResolver, tenantResolver,
                listeners.orderedStream().toList());
    }

    @Bean(name = "rbac")
    @ConditionalOnMissingBean(name = "rbac")
    public RbacExpressions rbac(RbacService rbacService) {
        return new RbacExpressions(rbacService);
    }

    @Bean
    @ConditionalOnMissingBean(PermissionEvaluator.class)
    public RbacPermissionEvaluator rbacPermissionEvaluator(RbacService rbacService) {
        return new RbacPermissionEvaluator(rbacService);
    }

    @Bean
    @ConditionalOnMissingBean
    public RbacAuthorityMapper rbacAuthorityMapper(RbacService rbacService, RbacProperties properties) {
        return new RbacAuthorityMapper(rbacService, properties.getAuthorities().getRolePrefix(),
                properties.getAuthorities().getPermissionPrefix());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(RbacManagementStore.class)
    public RbacAdministration rbacAdministration(RbacManagementStore store, PermissionResolver resolver,
                                                 SubjectIdResolver subjectIdResolver,
                                                 ApplicationEventPublisher publisher,
                                                 ObjectProvider<RbacChangeListener> extraListeners) {
        RbacAdministration administration = new RbacAdministration(store);
        EvictablePermissionResolver cache = resolver instanceof EvictablePermissionResolver e ? e : null;
        administration.addListener(new SpringRbacChangeListener(publisher, cache, subjectIdResolver));
        extraListeners.orderedStream().forEach(administration::addListener);
        return administration;
    }

    @Bean
    @ConditionalOnBean(RbacAdministration.class)
    public RbacSeedInitializer rbacSeedInitializer(RbacAdministration administration, RbacProperties properties) {
        return new RbacSeedInitializer(administration, properties.getSeed());
    }
}
