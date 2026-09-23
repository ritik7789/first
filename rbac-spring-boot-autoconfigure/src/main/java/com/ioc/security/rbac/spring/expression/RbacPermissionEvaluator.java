package com.ioc.security.rbac.spring.expression;

import com.ioc.security.rbac.spring.Logical;
import com.ioc.security.rbac.spring.RbacService;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.util.List;

/**
 * Bridges Spring Security's {@code hasPermission(...)} expressions to RBAC:
 * <ul>
 *   <li>{@code hasPermission(#id, 'booking', 'cancel')} checks {@code booking:cancel}</li>
 *   <li>{@code hasPermission(#booking, 'booking:cancel')} checks {@code booking:cancel}</li>
 *   <li>{@code hasPermission(#booking, 'cancel')} checks {@code <simple class name>:cancel}, e.g. {@code booking:cancel}</li>
 * </ul>
 * The target object is not inspected; plug in your own {@link PermissionEvaluator} for ownership rules.
 */
public class RbacPermissionEvaluator implements PermissionEvaluator {

    private final RbacService rbacService;

    public RbacPermissionEvaluator(RbacService rbacService) {
        this.rbacService = rbacService;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        String code = permission.toString();
        if (!code.contains(":") && targetDomainObject != null) {
            code = targetDomainObject.getClass().getSimpleName() + ":" + code;
        }
        return rbacService.hasPermissions(authentication, List.of(code), Logical.ALL, "hasPermission");
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
                                 Object permission) {
        return rbacService.hasPermissions(authentication, List.of(targetType + ":" + permission), Logical.ALL,
                "hasPermission");
    }
}
