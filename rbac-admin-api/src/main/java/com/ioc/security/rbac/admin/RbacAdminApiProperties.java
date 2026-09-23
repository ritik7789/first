package com.ioc.security.rbac.admin;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code rbac.admin-api.*} properties.
 */
@ConfigurationProperties(prefix = "rbac.admin-api")
public class RbacAdminApiProperties {

    /**
     * Expose the RBAC management REST API.
     */
    private boolean enabled = false;

    /**
     * Base path of the API.
     */
    private String basePath = "/rbac";

    /**
     * Permission required to read roles, permissions and assignments.
     */
    private String readPermission = "rbac:read";

    /**
     * Permission required to change roles, permissions and assignments. Role and permission definitions require it
     * globally; assignments require it in the tenant of the assignment.
     */
    private String managePermission = "rbac:manage";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getBasePath() {
        return basePath;
    }

    public void setBasePath(String basePath) {
        this.basePath = basePath;
    }

    public String getReadPermission() {
        return readPermission;
    }

    public void setReadPermission(String readPermission) {
        this.readPermission = readPermission;
    }

    public String getManagePermission() {
        return managePermission;
    }

    public void setManagePermission(String managePermission) {
        this.managePermission = managePermission;
    }
}
