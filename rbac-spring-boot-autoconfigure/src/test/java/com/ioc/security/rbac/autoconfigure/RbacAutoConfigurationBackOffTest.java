package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.spi.RbacStore;
import com.ioc.security.rbac.core.store.InMemoryRbacStore;
import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.subject.SubjectIdResolver;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RbacAutoConfigurationBackOffTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(RbacStoreAutoConfiguration.class, RbacAutoConfiguration.class,
                    RbacMethodSecurityAutoConfiguration.class));

    @Test
    void defaultsToInMemoryStore() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(InMemoryRbacStore.class);
            assertThat(ctx).hasSingleBean(RbacService.class);
            assertThat(ctx).hasSingleBean(RbacAdministration.class);
            assertThat(ctx).hasBean("rbac");
        });
    }

    @Test
    void disabledSwitchRemovesEverything() {
        runner.withPropertyValues("rbac.enabled=false")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(RbacService.class).doesNotHaveBean(RbacStore.class));
    }

    @Test
    void readOnlyCustomStoreDisablesAdministration() {
        RbacStore readOnly = new RbacStore() {
            public Optional<Role> findRole(String roleName) {
                return Optional.of(Role.of("R", "x:y"));
            }

            public List<Role> findAllRoles() {
                return List.of(Role.of("R", "x:y"));
            }

            public Optional<Permission> findPermission(String code) {
                return Optional.empty();
            }

            public List<Permission> findAllPermissions() {
                return List.of();
            }

            public List<RoleAssignment> findAssignments(String subjectId) {
                return List.of(RoleAssignment.global(subjectId, "R"));
            }
        };
        runner.withBean(RbacStore.class, () -> readOnly).run(ctx -> {
            assertThat(ctx).doesNotHaveBean(InMemoryRbacStore.class);
            assertThat(ctx).doesNotHaveBean(RbacAdministration.class);
            assertThat(ctx.getBean(RbacService.class).permissionsOf("anyone", null).permissions())
                    .containsExactly("x:y");
        });
    }

    @Test
    void customSubjectResolverIsUsed() {
        SubjectIdResolver custom = authentication -> "fixed";
        runner.withBean(SubjectIdResolver.class, () -> custom)
                .run(ctx -> assertThat(ctx.getBean(SubjectIdResolver.class)).isSameAs(custom));
    }
}
