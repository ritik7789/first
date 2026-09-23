package com.ioc.security.rbac.test;

import com.ioc.security.rbac.core.spi.PermissionResolver;
import com.ioc.security.rbac.core.spi.RbacStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Active only when {@code rbac-test} is on the (test) classpath: lets {@link WithRbacUser} override resolution.
 */
@AutoConfiguration
public class RbacTestAutoConfiguration {

    @Bean
    static BeanPostProcessor rbacTestPermissionResolverPostProcessor(ObjectProvider<RbacStore> store) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof PermissionResolver resolver && !(bean instanceof TestOverridePermissionResolver)) {
                    return new TestOverridePermissionResolver(resolver, store);
                }
                return bean;
            }
        };
    }
}
