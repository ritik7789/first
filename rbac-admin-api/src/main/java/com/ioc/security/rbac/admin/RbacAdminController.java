package com.ioc.security.rbac.admin;

import com.ioc.security.rbac.admin.RbacAdminDtos.AssignmentRequest;
import com.ioc.security.rbac.admin.RbacAdminDtos.EffectivePermissionsResponse;
import com.ioc.security.rbac.admin.RbacAdminDtos.PermissionCodesRequest;
import com.ioc.security.rbac.admin.RbacAdminDtos.PermissionRequest;
import com.ioc.security.rbac.admin.RbacAdminDtos.RoleRequest;
import com.ioc.security.rbac.admin.RbacAdminDtos.RoleUpdateRequest;
import com.ioc.security.rbac.core.RbacValidationException;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.model.Identifiers;
import com.ioc.security.rbac.core.model.Permission;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.spring.RbacService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;

/**
 * REST API to manage RBAC data. Enabled with {@code rbac.admin-api.enabled=true}.
 */
@RestController
@RequestMapping("${rbac.admin-api.base-path:/rbac}")
public class RbacAdminController {

    private final RbacAdministration administration;
    private final RbacService rbacService;
    private final RbacAdminGuard guard;

    public RbacAdminController(RbacAdministration administration, RbacService rbacService, RbacAdminGuard guard) {
        this.administration = administration;
        this.rbacService = rbacService;
        this.guard = guard;
    }

    // ---------------------------------------------------------------- current user

    /** Effective roles and permissions of the caller, e.g. for a front-end to show or hide features. */
    @GetMapping("/me")
    public EffectivePermissionsResponse me() {
        guard.caller();
        return toResponse(rbacService.currentPermissions());
    }

    // ---------------------------------------------------------------- permissions

    @GetMapping("/permissions")
    public List<Permission> permissions() {
        guard.requireRead();
        return administration.listPermissions();
    }

    @PostMapping("/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    public Permission createPermission(@RequestBody PermissionRequest request) {
        guard.requireGlobalManage();
        return administration.createPermission(new Permission(request.code(), request.description()));
    }

    @DeleteMapping("/permissions/{code}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deletePermission(@PathVariable String code) {
        guard.requireGlobalManage();
        administration.deletePermission(code);
    }

    // ---------------------------------------------------------------- roles

    @GetMapping("/roles")
    public List<Role> roles() {
        guard.requireRead();
        return administration.listRoles();
    }

    @GetMapping("/roles/{name}")
    public Role role(@PathVariable String name) {
        guard.requireRead();
        return administration.getRole(name);
    }

    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    public Role createRole(@RequestBody RoleRequest request) {
        EffectivePermissions caller = guard.requireGlobalManage();
        Role role = new Role(request.name(), request.description(), request.parent(),
                request.permissions() == null ? Set.of() : request.permissions());
        guard.requireCanGrant(caller, role.permissions());
        guard.requireCanGrantRole(caller, role.parentName());
        return administration.createRole(role, false);
    }

    @PutMapping("/roles/{name}")
    public Role updateRole(@PathVariable String name, @RequestBody RoleUpdateRequest request) {
        EffectivePermissions caller = guard.requireGlobalManage();
        Role existing = administration.getRole(name);
        if (request.parent() != null && !request.parent().equals(existing.parentName())) {
            guard.requireCanGrantRole(caller, request.parent());
        }
        return administration.updateRole(name, request.description(), request.parent());
    }

    @DeleteMapping("/roles/{name}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteRole(@PathVariable String name) {
        guard.requireGlobalManage();
        administration.deleteRole(name);
    }

    @PostMapping("/roles/{name}/permissions")
    public Role addRolePermissions(@PathVariable String name, @RequestBody PermissionCodesRequest request) {
        EffectivePermissions caller = guard.requireGlobalManage();
        guard.requireCanGrant(caller, guard.nullSafe(request.permissions()).stream()
                .map(Identifiers::permissionCode).toList());
        return administration.addPermissionsToRole(name, request.permissions(), false);
    }

    @DeleteMapping("/roles/{name}/permissions/{code}")
    public Role removeRolePermission(@PathVariable String name, @PathVariable String code) {
        guard.requireGlobalManage();
        return administration.removePermissionFromRole(name, code);
    }

    @GetMapping("/roles/{name}/assignments")
    public List<RoleAssignment> roleAssignments(@PathVariable String name) {
        guard.requireRead();
        return administration.getAssignmentsByRole(name);
    }

    // ---------------------------------------------------------------- subjects

    @GetMapping("/subjects/{subjectId}/assignments")
    public List<RoleAssignment> assignments(@PathVariable String subjectId) {
        guard.requireRead();
        return administration.getAssignments(subjectId);
    }

    @PostMapping("/subjects/{subjectId}/assignments")
    @ResponseStatus(HttpStatus.CREATED)
    public RoleAssignment assign(@PathVariable String subjectId, @RequestBody AssignmentRequest request) {
        if (request.role() == null) {
            throw new RbacValidationException("role is required");
        }
        String tenant = Identifiers.tenantId(request.tenantId());
        EffectivePermissions caller = guard.requireManage(tenant);
        guard.requireCanGrantRole(caller, request.role());
        return administration.assignRole(new RoleAssignment(subjectId, request.role(), tenant, request.expiresAt(),
                guard.caller(), null));
    }

    @DeleteMapping("/subjects/{subjectId}/assignments/{role}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable String subjectId, @PathVariable String role,
                       @RequestParam(required = false) String tenantId) {
        guard.requireManage(Identifiers.tenantId(tenantId));
        administration.revokeRole(subjectId, role, tenantId);
    }

    @GetMapping("/subjects/{subjectId}/permissions")
    public EffectivePermissionsResponse effectivePermissions(@PathVariable String subjectId,
                                                             @RequestParam(required = false) String tenantId) {
        guard.requireRead();
        return toResponse(rbacService.permissionsOf(Identifiers.subjectId(subjectId), Identifiers.tenantId(tenantId)));
    }

    private EffectivePermissionsResponse toResponse(EffectivePermissions effective) {
        return new EffectivePermissionsResponse(effective.subjectId(), effective.tenantId(), effective.roles(),
                effective.permissions(), rbacService.isSuperAdmin(effective));
    }
}
