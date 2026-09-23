package com.ioc.security.rbac.core;

import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.spi.RbacChangeListener.ChangeType;
import com.ioc.security.rbac.core.store.InMemoryRbacStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RbacAdministrationTest {

    private InMemoryRbacStore store;
    private RbacAdministration admin;
    private final List<ChangeType> changes = new ArrayList<>();

    @BeforeEach
    void setUp() {
        store = new InMemoryRbacStore();
        admin = new RbacAdministration(store);
        admin.addListener((type, target, detail) -> changes.add(type));
    }

    @Test
    void rejectsDuplicatesAndMissingReferences() {
        admin.createPermission(Permission.of("flight:read"));
        assertThatThrownBy(() -> admin.createPermission(Permission.of("FLIGHT:READ")))
                .isInstanceOf(RbacConflictException.class);
        assertThatThrownBy(() -> admin.createRole(Role.of("A", "flight:cancel"), false))
                .isInstanceOf(RbacNotFoundException.class);
        assertThatThrownBy(() -> admin.createRole(Role.of("A").withParent("MISSING"), false))
                .isInstanceOf(RbacNotFoundException.class);
        assertThatThrownBy(() -> admin.assignRole(RoleAssignment.global("u", "MISSING")))
                .isInstanceOf(RbacNotFoundException.class);
    }

    @Test
    void rejectsHierarchyCycles() {
        admin.createRole(Role.of("A"), false);
        admin.createRole(Role.of("B").withParent("A"), false);
        admin.createRole(Role.of("C").withParent("B"), false);

        assertThatThrownBy(() -> admin.updateRole("A", null, "C")).isInstanceOf(RbacValidationException.class);
        assertThatThrownBy(() -> admin.updateRole("A", null, "A")).isInstanceOf(RbacValidationException.class);
        assertThatThrownBy(() -> admin.deleteRole("A")).isInstanceOf(RbacConflictException.class);
    }

    @Test
    void deletingPermissionRemovesItFromRoles() {
        admin.createRole(Role.of("AGENT", "booking:read", "booking:create"), true);
        admin.deletePermission("booking:create");
        assertThat(admin.getRole("AGENT").permissions()).containsExactly("booking:read");
    }

    @Test
    void deletingRoleRemovesAssignments() {
        admin.createRole(Role.of("AGENT"), false);
        admin.assignRole(RoleAssignment.global("u", "AGENT"));
        admin.deleteRole("AGENT");
        assertThat(admin.getAssignments("u")).isEmpty();
    }

    @Test
    void ensureMethodsAreIdempotentAndAdditive() {
        admin.ensureRole(Role.of("AGENT", "booking:read"));
        admin.ensureRole(Role.of("AGENT", "booking:read", "booking:create"));
        admin.ensureRole(Role.of("AGENT", "booking:read"));
        admin.ensureAssignment(RoleAssignment.global("u", "AGENT"));
        admin.ensureAssignment(RoleAssignment.global("u", "AGENT"));

        assertThat(admin.getRole("AGENT").permissions()).containsExactlyInAnyOrder("booking:read", "booking:create");
        assertThat(admin.getAssignments("u")).hasSize(1);
    }

    @Test
    void assignmentsAreKeyedBySubjectRoleAndTenant() {
        admin.createRole(Role.of("AGENT"), false);
        admin.assignRole(RoleAssignment.global("u", "AGENT"));
        admin.assignRole(RoleAssignment.forTenant("u", "AGENT", "AI"));
        admin.assignRole(RoleAssignment.forTenant("u", "AGENT", "AI"));
        assertThat(admin.getAssignments("u")).hasSize(2);

        admin.revokeRole("u", "AGENT", "AI");
        assertThat(admin.getAssignments("u")).extracting(RoleAssignment::tenantId).containsExactly((String) null);
        assertThatThrownBy(() -> admin.revokeRole("u", "AGENT", "AI")).isInstanceOf(RbacNotFoundException.class);
    }

    @Test
    void rejectsExpiryInThePast() {
        admin.createRole(Role.of("AGENT"), false);
        assertThatThrownBy(() -> admin.assignRole(
                new RoleAssignment("u", "AGENT", null, Instant.now().minusSeconds(5), null, null)))
                .isInstanceOf(RbacValidationException.class);
    }

    @Test
    void notifiesListeners() {
        admin.createRole(new Role("AGENT", "desc", null, Set.of("booking:read")), true);
        admin.assignRole(RoleAssignment.global("u", "AGENT"));
        assertThat(changes).containsExactly(ChangeType.ROLE_CREATED, ChangeType.ROLE_ASSIGNED);
    }
}
