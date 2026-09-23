package com.ioc.security.rbac.spring;

import com.ioc.security.rbac.core.engine.AccessEvaluator;
import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.spi.PermissionResolver;
import com.ioc.security.rbac.spring.subject.SubjectIdResolver;
import com.ioc.security.rbac.spring.subject.TenantResolver;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Main programmatic entry point. Answers authorisation questions for the current Spring Security
 * {@link Authentication} (or an explicit subject) and throws {@link AccessDeniedException} from {@code check*}
 * methods, so the host's normal 403 handling applies.
 */
public class RbacService {

    public static final String PROGRAMMATIC = "programmatic";

    private final PermissionResolver resolver;
    private final AccessEvaluator evaluator;
    private final SubjectIdResolver subjectIdResolver;
    private final TenantResolver tenantResolver;
    private final List<RbacDecisionListener> listeners;

    public RbacService(PermissionResolver resolver, AccessEvaluator evaluator, SubjectIdResolver subjectIdResolver,
                       TenantResolver tenantResolver, List<RbacDecisionListener> listeners) {
        this.resolver = resolver;
        this.evaluator = evaluator;
        this.subjectIdResolver = subjectIdResolver;
        this.tenantResolver = tenantResolver;
        this.listeners = List.copyOf(listeners);
    }

    // ---------------------------------------------------------------- current subject

    public Optional<String> currentSubjectId() {
        return Optional.ofNullable(subjectIdResolver.resolve(currentAuthentication()));
    }

    public Optional<String> currentTenantId() {
        return Optional.ofNullable(tenantResolver.resolve(currentAuthentication()));
    }

    /**
     * Effective roles and permissions of the current subject; empty when unauthenticated.
     */
    public EffectivePermissions currentPermissions() {
        return permissionsOf(currentAuthentication());
    }

    public boolean hasPermission(String permission) {
        return hasPermissions(currentAuthentication(), List.of(permission), Logical.ALL, PROGRAMMATIC);
    }

    public boolean hasAllPermissions(String... permissions) {
        return hasPermissions(currentAuthentication(), Arrays.asList(permissions), Logical.ALL, PROGRAMMATIC);
    }

    public boolean hasAnyPermission(String... permissions) {
        return hasPermissions(currentAuthentication(), Arrays.asList(permissions), Logical.ANY, PROGRAMMATIC);
    }

    public boolean hasRole(String role) {
        return hasRoles(currentAuthentication(), List.of(role), Logical.ALL, PROGRAMMATIC);
    }

    public boolean hasAnyRole(String... roles) {
        return hasRoles(currentAuthentication(), Arrays.asList(roles), Logical.ANY, PROGRAMMATIC);
    }

    /** Throws unless the current subject holds every given permission. */
    public void checkPermission(String... permissions) {
        check(currentAuthentication(), AccessDecision.Type.PERMISSION, Arrays.asList(permissions), Logical.ALL,
                PROGRAMMATIC);
    }

    /** Throws unless the current subject holds at least one of the given permissions. */
    public void checkAnyPermission(String... permissions) {
        check(currentAuthentication(), AccessDecision.Type.PERMISSION, Arrays.asList(permissions), Logical.ANY,
                PROGRAMMATIC);
    }

    /** Throws unless the current subject holds the role. */
    public void checkRole(String role) {
        check(currentAuthentication(), AccessDecision.Type.ROLE, List.of(role), Logical.ALL, PROGRAMMATIC);
    }

    // ---------------------------------------------------------------- explicit authentication / subject

    public EffectivePermissions permissionsOf(Authentication authentication) {
        String subjectId = subjectIdResolver.resolve(authentication);
        String tenantId = tenantResolver.resolve(authentication);
        return subjectId == null ? EffectivePermissions.none(null, tenantId) : resolver.resolve(subjectId, tenantId);
    }

    /** Resolves permissions of any subject, e.g. for back-office tooling or message consumers. */
    public EffectivePermissions permissionsOf(String subjectId, String tenantId) {
        return resolver.resolve(subjectId, tenantId);
    }

    public boolean isSuperAdmin(EffectivePermissions effective) {
        return evaluator.isSuperAdmin(effective);
    }

    /** The configured super-admin role, or {@code null} when none is configured. */
    public String superAdminRole() {
        return evaluator.superAdminRole();
    }

    public boolean hasPermission(EffectivePermissions effective, String permission) {
        return evaluator.hasPermission(effective, permission);
    }

    public boolean hasPermissions(Authentication authentication, List<String> permissions, Logical logical,
                                  String source) {
        return decide(authentication, AccessDecision.Type.PERMISSION, permissions, logical, source);
    }

    public boolean hasRoles(Authentication authentication, List<String> roles, Logical logical, String source) {
        return decide(authentication, AccessDecision.Type.ROLE, roles, logical, source);
    }

    /**
     * Enforces the requirement for the given authentication.
     *
     * @throws AuthenticationCredentialsNotFoundException when not authenticated (results in 401)
     * @throws AccessDeniedException                      when authenticated but not allowed (results in 403)
     */
    public void check(Authentication authentication, AccessDecision.Type type, List<String> required,
                      Logical logical, String source) {
        if (subjectIdResolver.resolve(authentication) == null) {
            throw new AuthenticationCredentialsNotFoundException("Authentication is required");
        }
        if (!decide(authentication, type, required, logical, source)) {
            throw new AccessDeniedException("Access denied: requires " + (logical == Logical.ALL ? "all" : "any")
                    + " of " + (type == AccessDecision.Type.PERMISSION ? "permissions " : "roles ") + required);
        }
    }

    // ---------------------------------------------------------------- internals

    private boolean decide(Authentication authentication, AccessDecision.Type type, List<String> required,
                           Logical logical, String source) {
        EffectivePermissions effective = permissionsOf(authentication);
        boolean granted;
        if (effective.subjectId() == null) {
            granted = false;
        } else if (type == AccessDecision.Type.PERMISSION) {
            granted = logical == Logical.ALL
                    ? evaluator.hasAllPermissions(effective, required)
                    : evaluator.hasAnyPermission(effective, required);
        } else {
            granted = logical == Logical.ALL
                    ? evaluator.hasAllRoles(effective, required)
                    : evaluator.hasAnyRole(effective, required);
        }
        if (!listeners.isEmpty()) {
            AccessDecision decision = new AccessDecision(effective.subjectId(), effective.tenantId(), type,
                    List.copyOf(required), logical, granted, source);
            listeners.forEach(l -> l.onDecision(decision));
        }
        return granted;
    }

    private static Authentication currentAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
