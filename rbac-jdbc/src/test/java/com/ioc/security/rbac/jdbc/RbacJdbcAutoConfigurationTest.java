package com.ioc.security.rbac.jdbc;

import com.ioc.security.rbac.autoconfigure.RbacAutoConfiguration;
import com.ioc.security.rbac.autoconfigure.RbacStoreAutoConfiguration;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.spi.RbacStore;
import com.ioc.security.rbac.core.store.InMemoryRbacStore;
import com.ioc.security.rbac.spring.RbacService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RbacJdbcAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(DataSourceAutoConfiguration.class,
                    RbacJdbcAutoConfiguration.class, RbacStoreAutoConfiguration.class, RbacAutoConfiguration.class))
            .withPropertyValues("spring.datasource.url=jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1");

    @Test
    void usesJdbcStoreAndSeedsIntoDatabase() {
        runner.withPropertyValues(
                        "rbac.jdbc.table-prefix=sec_",
                        "rbac.seed.roles.ADMIN.permissions=*",
                        "rbac.seed.assignments[0].subject=admin",
                        "rbac.seed.assignments[0].role=ADMIN")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(JdbcRbacStore.class).doesNotHaveBean(InMemoryRbacStore.class);
                    assertThat(ctx).hasSingleBean(RbacAdministration.class);
                    JdbcTemplate jdbc = new JdbcTemplate(ctx.getBean(DataSource.class));
                    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sec_subject_role", Integer.class)).isEqualTo(1);
                    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM \"sec_schema_history\"", Integer.class)).isPositive();
                    assertThat(ctx.getBean(RbacService.class).permissionsOf("admin", null).permissions())
                            .containsExactly("*");
                });
    }

    @Test
    void fallsBackToInMemoryWhenDisabled() {
        runner.withPropertyValues("rbac.jdbc.enabled=false")
                .run(ctx -> assertThat(ctx.getBean(RbacStore.class)).isInstanceOf(InMemoryRbacStore.class));
    }

    @Test
    void schemaInitNoneDoesNotRunFlyway() {
        runner.withPropertyValues("rbac.jdbc.schema.init=none")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(RbacSchemaMigrator.class));
    }

    @Test
    void coexistsWithHostFlyway() {
        runner.withConfiguration(AutoConfigurations.of(FlywayAutoConfiguration.class))
                .withPropertyValues("spring.flyway.locations=classpath:db/host-migration")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    JdbcTemplate jdbc = new JdbcTemplate(ctx.getBean(DataSource.class));
                    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM host_table", Integer.class)).isZero();
                    assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM rbac_role", Integer.class)).isZero();
                });
    }
}
