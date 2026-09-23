package com.ioc.security.rbac.jdbc;

import com.ioc.security.rbac.autoconfigure.RbacStoreAutoConfiguration;
import com.ioc.security.rbac.core.spi.RbacStore;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationInitializer;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * Registers the {@link JdbcRbacStore} (and the Flyway based schema migrator) when a DataSource is available.
 */
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class},
        before = RbacStoreAutoConfiguration.class)
@ConditionalOnClass(JdbcTemplate.class)
@ConditionalOnBean(DataSource.class)
@ConditionalOnProperty(prefix = "rbac", name = {"enabled", "jdbc.enabled"}, havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(JdbcRbacProperties.class)
public class RbacJdbcAutoConfiguration {

    static DataSource rbacDataSource(BeanFactory beanFactory, JdbcRbacProperties properties) {
        return properties.getDataSourceBean() == null
                ? beanFactory.getBean(DataSource.class)
                : beanFactory.getBean(properties.getDataSourceBean(), DataSource.class);
    }

    @Bean
    @ConditionalOnMissingBean(RbacStore.class)
    public JdbcRbacStore jdbcRbacStore(BeanFactory beanFactory, JdbcRbacProperties properties,
                                       ObjectProvider<RbacSchemaMigrator> migrator) {
        migrator.ifAvailable(m -> { /* ensure tables exist before the store is used */ });
        return new JdbcRbacStore(rbacDataSource(beanFactory, properties), properties.getTablePrefix(),
                properties.getSchema().getName());
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.flywaydb.core.Flyway")
    @ConditionalOnProperty(prefix = "rbac.jdbc.schema", name = "init", havingValue = "flyway", matchIfMissing = true)
    static class FlywayConfiguration {

        @Bean
        @ConditionalOnMissingBean
        RbacSchemaMigrator rbacSchemaMigrator(BeanFactory beanFactory, JdbcRbacProperties properties,
                                              ObjectProvider<FlywayMigrationInitializer> hostFlyway) {
            // Let the application's own Flyway migrate first: otherwise it would find a non-empty schema (our tables)
            // and either fail or, with baseline-on-migrate, skip its own first migration.
            hostFlyway.orderedStream().forEach(initializer -> { });
            return new RbacSchemaMigrator(rbacDataSource(beanFactory, properties), properties);
        }
    }
}
