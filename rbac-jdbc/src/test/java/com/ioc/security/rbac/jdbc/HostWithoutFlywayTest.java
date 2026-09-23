package com.ioc.security.rbac.jdbc;

import com.ioc.security.rbac.autoconfigure.RbacAutoConfiguration;
import com.ioc.security.rbac.autoconfigure.RbacStoreAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.env.MockEnvironment;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Existing applications that never used Flyway must start unchanged after adding the starter.
 */
class HostWithoutFlywayTest {

    private final RbacFlywayEnvironmentPostProcessor postProcessor = new RbacFlywayEnvironmentPostProcessor();

    @Test
    void disablesHostFlywayWhenHostHasNoMigrations() {
        MockEnvironment environment = new MockEnvironment();
        postProcessor.postProcessEnvironment(environment, new SpringApplication());
        assertThat(environment.getProperty("spring.flyway.enabled")).isEqualTo("false");
    }

    @Test
    void leavesHostFlywayAloneWhenHostHasMigrations() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.flyway.locations", "classpath:db/host-migration");
        postProcessor.postProcessEnvironment(environment, new SpringApplication());
        assertThat(environment.getProperty("spring.flyway.enabled")).isNull();
    }

    @Test
    void respectsExplicitConfiguration() {
        MockEnvironment environment = new MockEnvironment().withProperty("spring.flyway.enabled", "true");
        postProcessor.postProcessEnvironment(environment, new SpringApplication());
        assertThat(environment.getProperty("spring.flyway.enabled")).isEqualTo("true");
    }

    @Test
    void existingSchemaStartsAndGetsRbacTables() {
        String url = "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(url, "sa", ""));
        jdbc.execute("CREATE TABLE legacy_orders (id INT)");

        MockEnvironment environment = new MockEnvironment();
        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class,
                        RbacJdbcAutoConfiguration.class, RbacStoreAutoConfiguration.class, RbacAutoConfiguration.class))
                .withPropertyValues("spring.datasource.url=" + url,
                        "spring.flyway.enabled=" + environment.getProperty("spring.flyway.enabled"))
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM rbac_role", Integer.class)).isZero();
                });
    }
}
