package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.core.spi.RbacStore;
import com.ioc.security.rbac.core.store.InMemoryRbacStore;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Fallback store: when neither the JDBC store nor a custom {@link RbacStore} bean is present, keep RBAC data in
 * memory (populated from {@code rbac.seed.*}).
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "rbac", name = "enabled", havingValue = "true", matchIfMissing = true)
public class RbacStoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(RbacStore.class)
    public InMemoryRbacStore inMemoryRbacStore() {
        LoggerFactory.getLogger(RbacStoreAutoConfiguration.class)
                .info("No persistent RBAC store configured; using in-memory store (data is lost on restart)");
        return new InMemoryRbacStore();
    }
}
