package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.spring.Logical;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * All {@code rbac.*} configuration properties.
 */
@ConfigurationProperties(prefix = "rbac")
public class RbacProperties {

    /**
     * Master switch. When false no RBAC beans are created and RBAC annotations are NOT enforced.
     */
    private boolean enabled = true;

    /**
     * Optional role whose holders pass every permission and role check. Disabled when empty.
     */
    private String superAdminRole;

    private final Subject subject = new Subject();
    private final MultiTenancy multiTenancy = new MultiTenancy();
    private final Cache cache = new Cache();
    private final Authorities authorities = new Authorities();
    private final Audit audit = new Audit();
    private final MethodSecurity methodSecurity = new MethodSecurity();
    private final Seed seed = new Seed();

    /**
     * URL based rules, applied when the host adds the {@code RbacUrlRules} customizer to its security chain.
     */
    private List<UrlRule> urlRules = new ArrayList<>();

    public static class Subject {

        /**
         * Token claim holding the subject id for OAuth2 resource servers (e.g. "sub", "preferred_username",
         * "user_id"). When empty, Authentication#getName() is used.
         */
        private String claim;

        public String getClaim() {
            return claim;
        }

        public void setClaim(String claim) {
            this.claim = claim;
        }
    }

    public static class MultiTenancy {

        /**
         * Enable tenant scoped role assignments. When disabled only global assignments are considered.
         */
        private boolean enabled = false;

        /**
         * HTTP header carrying the tenant id.
         */
        private String header = "X-Tenant-Id";

        /**
         * Token claim carrying the tenant id; takes precedence over the header when present.
         */
        private String claim;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public String getClaim() {
            return claim;
        }

        public void setClaim(String claim) {
            this.claim = claim;
        }
    }

    public static class Cache {

        /**
         * Cache resolved permissions per subject and tenant.
         */
        private boolean enabled = true;

        /**
         * How long resolved permissions are cached. Bounds how long a change made on another node takes effect.
         */
        private Duration ttl = Duration.ofMinutes(5);

        /**
         * Maximum number of cached (subject, tenant) entries.
         */
        private int maxEntries = 10_000;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }

        public int getMaxEntries() {
            return maxEntries;
        }

        public void setMaxEntries(int maxEntries) {
            this.maxEntries = maxEntries;
        }
    }

    public static class Authorities {

        /**
         * Prefix used when RBAC roles are exposed as Spring Security authorities.
         */
        private String rolePrefix = "ROLE_";

        /**
         * Prefix used when RBAC permissions are exposed as Spring Security authorities.
         */
        private String permissionPrefix = "";

        public String getRolePrefix() {
            return rolePrefix;
        }

        public void setRolePrefix(String rolePrefix) {
            this.rolePrefix = rolePrefix;
        }

        public String getPermissionPrefix() {
            return permissionPrefix;
        }

        public void setPermissionPrefix(String permissionPrefix) {
            this.permissionPrefix = permissionPrefix;
        }
    }

    public static class Audit {

        /**
         * Publish access decision events and log RBAC data changes.
         */
        private boolean enabled = true;

        /**
         * Also publish events for granted decisions (denied decisions are always published when audit is enabled).
         */
        private boolean logGranted = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isLogGranted() {
            return logGranted;
        }

        public void setLogGranted(boolean logGranted) {
            this.logGranted = logGranted;
        }
    }

    public static class MethodSecurity {

        /**
         * Enforce @RequiresPermission / @RequiresRole annotations.
         */
        private boolean enabled = true;

        /**
         * Order of the RBAC method interceptor relative to other advisors (lower runs first).
         */
        private int order = 100;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getOrder() {
            return order;
        }

        public void setOrder(int order) {
            this.order = order;
        }
    }

    public static class UrlRule {

        /**
         * Ant / path patterns, e.g. /api/flights/**.
         */
        private List<String> patterns = new ArrayList<>();

        /**
         * HTTP methods the rule applies to; all methods when empty.
         */
        private List<String> methods = new ArrayList<>();

        /**
         * Required permissions.
         */
        private List<String> permissions = new ArrayList<>();

        /**
         * Required roles.
         */
        private List<String> roles = new ArrayList<>();

        /**
         * Whether all or any of the listed permissions / roles are required.
         */
        private Logical logical = Logical.ALL;

        public List<String> getPatterns() {
            return patterns;
        }

        public void setPatterns(List<String> patterns) {
            this.patterns = patterns;
        }

        /**
         * Convenience alias for a single pattern.
         */
        public void setPattern(String pattern) {
            this.patterns = new ArrayList<>(List.of(pattern));
        }

        public List<String> getMethods() {
            return methods;
        }

        public void setMethods(List<String> methods) {
            this.methods = methods;
        }

        public List<String> getPermissions() {
            return permissions;
        }

        public void setPermissions(List<String> permissions) {
            this.permissions = permissions;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }

        public Logical getLogical() {
            return logical;
        }

        public void setLogical(Logical logical) {
            this.logical = logical;
        }
    }

    public static class Seed {

        /**
         * Permissions to create at start-up (code -> description).
         */
        private Map<String, String> permissions = new LinkedHashMap<>();

        /**
         * Roles to create at start-up. Existing roles only get missing permissions added.
         */
        private Map<String, RoleSeed> roles = new LinkedHashMap<>();

        /**
         * Role assignments to create at start-up (e.g. the first administrator).
         */
        private List<AssignmentSeed> assignments = new ArrayList<>();

        public Map<String, String> getPermissions() {
            return permissions;
        }

        public void setPermissions(Map<String, String> permissions) {
            this.permissions = permissions;
        }

        public Map<String, RoleSeed> getRoles() {
            return roles;
        }

        public void setRoles(Map<String, RoleSeed> roles) {
            this.roles = roles;
        }

        public List<AssignmentSeed> getAssignments() {
            return assignments;
        }

        public void setAssignments(List<AssignmentSeed> assignments) {
            this.assignments = assignments;
        }
    }

    public static class RoleSeed {

        private String description;
        private String parent;
        private Set<String> permissions = new LinkedHashSet<>();

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getParent() {
            return parent;
        }

        public void setParent(String parent) {
            this.parent = parent;
        }

        public Set<String> getPermissions() {
            return permissions;
        }

        public void setPermissions(Set<String> permissions) {
            this.permissions = permissions;
        }
    }

    public static class AssignmentSeed {

        private String subject;
        private String role;
        private String tenant;

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public String getTenant() {
            return tenant;
        }

        public void setTenant(String tenant) {
            this.tenant = tenant;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getSuperAdminRole() {
        return superAdminRole;
    }

    public void setSuperAdminRole(String superAdminRole) {
        this.superAdminRole = superAdminRole;
    }

    public Subject getSubject() {
        return subject;
    }

    public MultiTenancy getMultiTenancy() {
        return multiTenancy;
    }

    public Cache getCache() {
        return cache;
    }

    public Authorities getAuthorities() {
        return authorities;
    }

    public Audit getAudit() {
        return audit;
    }

    public MethodSecurity getMethodSecurity() {
        return methodSecurity;
    }

    public Seed getSeed() {
        return seed;
    }

    public List<UrlRule> getUrlRules() {
        return urlRules;
    }

    public void setUrlRules(List<UrlRule> urlRules) {
        this.urlRules = urlRules;
    }
}
