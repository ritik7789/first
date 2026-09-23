package com.ioc.security.rbac.core;

import com.ioc.security.rbac.core.engine.AccessEvaluator;
import com.ioc.security.rbac.core.engine.HierarchicalPermissionResolver;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.engine.WildcardPermissionMatcher;
import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.store.InMemoryRbacStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PermissionResolutionTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private InMemoryRbacStore store;
    private RbacAdministration admin;
    private HierarchicalPermissionResolver resolver;
    private final AccessEvaluator evaluator = new AccessEvaluator(new WildcardPermissionMatcher(), "SUPER_ADMIN");

    @BeforeEach
    void setUp() {
        store = new InMemoryRbacStore();
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        admin = new RbacAdministration(store, clock);
        resolver = new HierarchicalPermissionResolver(store, clock);

        admin.createRole(Role.of("PASSENGER", "booking:read", "flight:read"), true);
        admin.createRole(Role.of("AGENT", "booking:create").withParent("PASSENGER"), true);
        admin.createRole(Role.of("SUPERVISOR", "booking:*").withParent("AGENT"), true);
        admin.createRole(Role.of("SUPER_ADMIN"), true);
    }

    @Test
    void inheritsPermissionsThroughHierarchy() {
        admin.assignRole(RoleAssignment.global("alice", "SUPERVISOR"));

        EffectivePermissions effective = resolver.resolve("alice", null);

        assertThat(effective.roles()).containsExactlyInAnyOrder("SUPERVISOR", "AGENT", "PASSENGER");
        assertThat(effective.permissions()).containsExactlyInAnyOrder(
                "booking:*", "booking:create", "booking:read", "flight:read");
        assertThat(evaluator.hasPermission(effective, "booking:cancel")).isTrue();
        assertThat(evaluator.hasPermission(effective, "flight:cancel")).isFalse();
    }

    @Test
    void tenantAssignmentsOnlyApplyInTheirTenant() {
        admin.assignRole(RoleAssignment.global("bob", "PASSENGER"));
        admin.assignRole(RoleAssignment.forTenant("bob", "AGENT", "AI"));

        assertThat(resolver.resolve("bob", "AI").roles()).contains("AGENT", "PASSENGER");
        assertThat(resolver.resolve("bob", "6E").roles()).containsExactly("PASSENGER");
        assertThat(resolver.resolve("bob", null).roles()).containsExactly("PASSENGER");
    }

    @Test
    void expiredAssignmentsAreIgnored() {
        store.saveAssignment(new RoleAssignment("carol", "AGENT", null, NOW.minusSeconds(1), null, null));
        store.saveAssignment(new RoleAssignment("carol", "PASSENGER", null, NOW.plusSeconds(60), null, null));

        assertThat(resolver.resolve("carol", null).roles()).containsExactly("PASSENGER");
    }

    @Test
    void superAdminPassesEveryCheck() {
        admin.assignRole(RoleAssignment.global("root", "SUPER_ADMIN"));
        EffectivePermissions effective = resolver.resolve("root", null);

        assertThat(evaluator.hasPermission(effective, "anything:goes")).isTrue();
        assertThat(evaluator.hasRole(effective, "AGENT")).isTrue();
    }

    @Test
    void unknownSubjectHasNothing() {
        EffectivePermissions effective = resolver.resolve("nobody", null);
        assertThat(effective.roles()).isEmpty();
        assertThat(evaluator.hasAnyPermission(effective, List.of("booking:read"))).isFalse();
    }
}
