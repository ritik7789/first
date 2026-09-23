package com.ioc.security.rbac.jdbc;

import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.spi.RbacManagementStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * {@link RbacManagementStore} using plain, portable SQL through {@link JdbcTemplate}. Works on any relational
 * database with a JDBC 4.2 driver. Timestamps are stored as UTC {@code TIMESTAMP} values.
 *
 * <p>Writes run in their own transaction unless one is already active (e.g. from the host's
 * {@code JpaTransactionManager} on the same DataSource), in which case they join it.
 */
public class JdbcRbacStore implements RbacManagementStore {

    static final String GLOBAL_TENANT = "*";
    private static final Pattern PREFIX = Pattern.compile("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)?");

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final String permissionTable;
    private final String roleTable;
    private final String rolePermissionTable;
    private final String subjectRoleTable;

    public JdbcRbacStore(DataSource dataSource, String tablePrefix) {
        this(dataSource, tablePrefix, null);
    }

    /**
     * @param schema optional schema name the tables live in
     */
    public JdbcRbacStore(DataSource dataSource, String tablePrefix, String schema) {
        String qualifier = (schema == null || schema.isBlank() ? "" : schema + ".") + tablePrefix;
        if (!PREFIX.matcher(qualifier).matches()) {
            throw new IllegalArgumentException("Invalid table prefix / schema: " + qualifier);
        }
        this.jdbc = new JdbcTemplate(dataSource);
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        this.permissionTable = qualifier + "permission";
        this.roleTable = qualifier + "role";
        this.rolePermissionTable = qualifier + "role_permission";
        this.subjectRoleTable = qualifier + "subject_role";
    }

    // ---------------------------------------------------------------- reads

    @Override
    public Optional<Role> findRole(String roleName) {
        List<Role> roles = jdbc.query("SELECT name, description, parent_name FROM " + roleTable + " WHERE name = ?",
                (rs, i) -> new Role(rs.getString(1), rs.getString(2), rs.getString(3), Set.of()), roleName);
        if (roles.isEmpty()) {
            return Optional.empty();
        }
        List<String> permissions = jdbc.queryForList(
                "SELECT permission_code FROM " + rolePermissionTable + " WHERE role_name = ?", String.class, roleName);
        return Optional.of(roles.get(0).withPermissions(permissions));
    }

    @Override
    public List<Role> findAllRoles() {
        Map<String, Set<String>> permissions = new HashMap<>();
        jdbc.query("SELECT role_name, permission_code FROM " + rolePermissionTable, rs -> {
            permissions.computeIfAbsent(rs.getString(1), k -> new HashSet<>()).add(rs.getString(2));
        });
        return jdbc.query("SELECT name, description, parent_name FROM " + roleTable + " ORDER BY name",
                (rs, i) -> new Role(rs.getString(1), rs.getString(2), rs.getString(3),
                        permissions.getOrDefault(rs.getString(1), Set.of())));
    }

    @Override
    public Optional<Permission> findPermission(String code) {
        return jdbc.query("SELECT code, description FROM " + permissionTable + " WHERE code = ?",
                PERMISSION_MAPPER, code).stream().findFirst();
    }

    @Override
    public List<Permission> findAllPermissions() {
        return jdbc.query("SELECT code, description FROM " + permissionTable + " ORDER BY code", PERMISSION_MAPPER);
    }

    @Override
    public List<RoleAssignment> findAssignments(String subjectId) {
        return jdbc.query("SELECT subject_id, role_name, tenant_id, expires_at, granted_by, granted_at FROM "
                + subjectRoleTable + " WHERE subject_id = ? ORDER BY role_name, tenant_id", ASSIGNMENT_MAPPER, subjectId);
    }

    @Override
    public List<RoleAssignment> findAssignmentsByRole(String roleName) {
        return jdbc.query("SELECT subject_id, role_name, tenant_id, expires_at, granted_by, granted_at FROM "
                + subjectRoleTable + " WHERE role_name = ? ORDER BY subject_id, tenant_id", ASSIGNMENT_MAPPER, roleName);
    }

    // ---------------------------------------------------------------- writes

    @Override
    public void insertPermission(Permission permission) {
        jdbc.update("INSERT INTO " + permissionTable + " (code, description, created_at) VALUES (?, ?, ?)",
                permission.code(), permission.description(), utc(Instant.now()));
    }

    @Override
    public void deletePermission(String code) {
        inTransaction(() -> {
            jdbc.update("DELETE FROM " + rolePermissionTable + " WHERE permission_code = ?", code);
            jdbc.update("DELETE FROM " + permissionTable + " WHERE code = ?", code);
            return null;
        });
    }

    @Override
    public void insertRole(Role role) {
        inTransaction(() -> {
            jdbc.update("INSERT INTO " + roleTable + " (name, description, parent_name, created_at) VALUES (?, ?, ?, ?)",
                    role.name(), role.description(), role.parentName(), utc(Instant.now()));
            addRolePermissions(role.name(), role.permissions());
            return null;
        });
    }

    @Override
    public void updateRole(Role role) {
        jdbc.update("UPDATE " + roleTable + " SET description = ?, parent_name = ? WHERE name = ?",
                role.description(), role.parentName(), role.name());
    }

    @Override
    public void deleteRole(String roleName) {
        inTransaction(() -> {
            jdbc.update("DELETE FROM " + subjectRoleTable + " WHERE role_name = ?", roleName);
            jdbc.update("DELETE FROM " + rolePermissionTable + " WHERE role_name = ?", roleName);
            jdbc.update("UPDATE " + roleTable + " SET parent_name = NULL WHERE parent_name = ?", roleName);
            jdbc.update("DELETE FROM " + roleTable + " WHERE name = ?", roleName);
            return null;
        });
    }

    @Override
    public void addRolePermissions(String roleName, Collection<String> permissionCodes) {
        if (permissionCodes.isEmpty()) {
            return;
        }
        List<Object[]> rows = new ArrayList<>();
        for (String code : permissionCodes) {
            rows.add(new Object[]{roleName, code});
        }
        jdbc.batchUpdate("INSERT INTO " + rolePermissionTable + " (role_name, permission_code) VALUES (?, ?)", rows);
    }

    @Override
    public void removeRolePermission(String roleName, String permissionCode) {
        jdbc.update("DELETE FROM " + rolePermissionTable + " WHERE role_name = ? AND permission_code = ?",
                roleName, permissionCode);
    }

    @Override
    public void saveAssignment(RoleAssignment a) {
        inTransaction(() -> {
            String tenant = toColumn(a.tenantId());
            jdbc.update("DELETE FROM " + subjectRoleTable + " WHERE subject_id = ? AND role_name = ? AND tenant_id = ?",
                    a.subjectId(), a.roleName(), tenant);
            jdbc.update("INSERT INTO " + subjectRoleTable
                            + " (subject_id, role_name, tenant_id, expires_at, granted_by, granted_at) VALUES (?, ?, ?, ?, ?, ?)",
                    a.subjectId(), a.roleName(), tenant, utc(a.expiresAt()), a.grantedBy(),
                    utc(a.grantedAt() != null ? a.grantedAt() : Instant.now()));
            return null;
        });
    }

    @Override
    public boolean deleteAssignment(String subjectId, String roleName, String tenantId) {
        return jdbc.update("DELETE FROM " + subjectRoleTable + " WHERE subject_id = ? AND role_name = ? AND tenant_id = ?",
                subjectId, roleName, toColumn(tenantId)) > 0;
    }

    @Override
    public <T> T inTransaction(Supplier<T> work) {
        return tx.execute(status -> work.get());
    }

    // ---------------------------------------------------------------- mapping

    private static final RowMapper<Permission> PERMISSION_MAPPER =
            (rs, i) -> new Permission(rs.getString(1), rs.getString(2));

    private static final RowMapper<RoleAssignment> ASSIGNMENT_MAPPER = (rs, i) -> new RoleAssignment(
            rs.getString(1), rs.getString(2), fromColumn(rs.getString(3)), instant(rs, 4), rs.getString(5),
            instant(rs, 6));

    private static String toColumn(String tenantId) {
        return tenantId == null ? GLOBAL_TENANT : tenantId;
    }

    private static String fromColumn(String tenantId) {
        return GLOBAL_TENANT.equals(tenantId) ? null : tenantId;
    }

    private static LocalDateTime utc(Instant instant) {
        return instant == null ? null : LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet rs, int column) throws SQLException {
        LocalDateTime value = rs.getObject(column, LocalDateTime.class);
        return value == null ? null : value.toInstant(ZoneOffset.UTC);
    }
}
