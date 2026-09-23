package com.ioc.security.rbac.jdbc;

import com.ioc.security.rbac.core.RbacConflictException;
import com.ioc.security.rbac.core.engine.HierarchicalPermissionResolver;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behaviour every database must support. Subclasses provide the DataSource.
 */
abstract class AbstractJdbcRbacStoreTest {

    protected JdbcRbacStore store;
    protected RbacAdministration admin;

    protected abstract DataSource dataSource();

    @BeforeEach
    void setUpStore() {
        DataSource dataSource = dataSource();
        JdbcRbacProperties properties = new JdbcRbacProperties();
        new RbacSchemaMigrator(dataSource, properties).afterPropertiesSet();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        for (String table : new String[]{"rbac_subject_role", "rbac_role_permission", "rbac_role", "rbac_permission"}) {
            if (table.equals("rbac_role")) {
                jdbc.update("UPDATE rbac_role SET parent_name = NULL");
            }
            jdbc.update("DELETE FROM " + table);
        }
        store = new JdbcRbacStore(dataSource, properties.getTablePrefix());
        admin = new RbacAdministration(store);
    }

    @Test
    void rolesPermissionsAndHierarchyRoundTrip() {
        admin.createPermission(new Permission("flight:read", "Read flights"));
        admin.createRole(new Role("PASSENGER", "Passenger", null, Set.of("flight:read", "booking:read")), true);
        admin.createRole(Role.of("AGENT", "booking:create").withParent("PASSENGER"), true);

        Role agent = store.findRole("AGENT").orElseThrow();
        assertThat(agent.parentName()).isEqualTo("PASSENGER");
        assertThat(agent.permissions()).containsExactly("booking:create");
        assertThat(store.findAllRoles()).extracting(Role::name).containsExactly("AGENT", "PASSENGER");
        assertThat(store.findAllPermissions()).extracting(Permission::code)
                .containsExactly("booking:create", "booking:read", "flight:read");
        assertThat(store.findPermission("flight:read").orElseThrow().description()).isEqualTo("Read flights");

        admin.addPermissionsToRole("AGENT", Set.of("booking:cancel"), true);
        admin.removePermissionFromRole("AGENT", "booking:create");
        assertThat(store.findRole("AGENT").orElseThrow().permissions()).containsExactly("booking:cancel");

        assertThatThrownBy(() -> admin.createRole(Role.of("AGENT"), false)).isInstanceOf(RbacConflictException.class);
    }

    @Test
    void assignmentsWithTenantsAndExpiry() {
        admin.createRole(Role.of("AGENT", "booking:create"), true);
        admin.createRole(Role.of("PASSENGER", "booking:read"), true);
        Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);

        admin.assignRole(new RoleAssignment("alice", "AGENT", "AI", expiry, "admin", null));
        admin.assignRole(RoleAssignment.global("alice", "PASSENGER"));
        admin.assignRole(RoleAssignment.forTenant("alice", "AGENT", "AI"));

        assertThat(store.findAssignments("alice")).hasSize(2);
        RoleAssignment tenantGrant = store.findAssignments("alice").stream()
                .filter(a -> "AI".equals(a.tenantId())).findFirst().orElseThrow();
        assertThat(tenantGrant.expiresAt()).isNull();
        assertThat(tenantGrant.grantedAt()).isNotNull();
        assertThat(store.findAssignmentsByRole("PASSENGER")).singleElement()
                .satisfies(a -> assertThat(a.tenantId()).isNull());

        HierarchicalPermissionResolver resolver = new HierarchicalPermissionResolver(store);
        EffectivePermissions inAi = resolver.resolve("alice", "AI");
        EffectivePermissions elsewhere = resolver.resolve("alice", "6E");
        assertThat(inAi.permissions()).containsExactlyInAnyOrder("booking:create", "booking:read");
        assertThat(elsewhere.permissions()).containsExactly("booking:read");

        admin.revokeRole("alice", "AGENT", "AI");
        assertThat(store.findAssignments("alice")).extracting(RoleAssignment::roleName).containsExactly("PASSENGER");
    }

    @Test
    void expiryIsStoredInUtc() {
        admin.createRole(Role.of("AGENT"), false);
        Instant expiry = Instant.parse("2099-06-30T23:30:00Z");
        admin.assignRole(new RoleAssignment("bob", "AGENT", null, expiry, null, null));
        assertThat(store.findAssignments("bob").get(0).expiresAt()).isEqualTo(expiry);
    }

    @Test
    void deletesCascadeToLinksAndAssignments() {
        admin.createRole(Role.of("AGENT", "booking:create", "booking:read"), true);
        admin.assignRole(RoleAssignment.global("carol", "AGENT"));

        admin.deletePermission("booking:create");
        assertThat(store.findRole("AGENT").orElseThrow().permissions()).containsExactly("booking:read");

        admin.deleteRole("AGENT");
        assertThat(store.findRole("AGENT")).isEmpty();
        assertThat(store.findAssignments("carol")).isEmpty();
    }

    @Test
    void migrationIsIdempotent() {
        new RbacSchemaMigrator(dataSource(), new JdbcRbacProperties()).afterPropertiesSet();
        assertThat(store.findAllRoles()).isEmpty();
    }
}
