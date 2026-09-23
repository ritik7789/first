package com.ioc.security.rbac.test;

import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.model.Identifiers;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.spi.EvictablePermissionResolver;
import com.ioc.security.rbac.core.spi.PermissionResolver;
import com.ioc.security.rbac.core.spi.RbacStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Decorates the application's resolver: when the current authentication comes from {@link WithRbacUser}, its grants
 * are used; otherwise resolution is delegated unchanged.
 */
public class TestOverridePermissionResolver implements EvictablePermissionResolver {

    private final PermissionResolver delegate;
    private final ObjectProvider<RbacStore> store;

    public TestOverridePermissionResolver(PermissionResolver delegate, ObjectProvider<RbacStore> store) {
        this.delegate = delegate;
        this.store = store;
    }

    @Override
    public EffectivePermissions resolve(String subjectId, String tenantId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof RbacTestAuthentication test && test.getName().equals(subjectId)) {
            return expand(test, tenantId);
        }
        return delegate.resolve(subjectId, tenantId);
    }

    private EffectivePermissions expand(RbacTestAuthentication test, String tenantId) {
        Set<String> roles = new LinkedHashSet<>();
        Set<String> permissions = new LinkedHashSet<>();
        test.getPermissions().forEach(p -> permissions.add(Identifiers.permissionCode(p)));
        RbacStore rbacStore = store.getIfAvailable();
        Deque<String> pending = new ArrayDeque<>(test.getRoles());
        while (!pending.isEmpty()) {
            String name = pending.poll();
            if (!roles.add(name) || rbacStore == null) {
                continue;
            }
            Optional<Role> role = rbacStore.findRole(name);
            role.ifPresent(r -> {
                permissions.addAll(r.permissions());
                if (r.parentName() != null) {
                    pending.add(r.parentName());
                }
            });
        }
        return new EffectivePermissions(test.getName(), tenantId, roles, permissions);
    }

    @Override
    public void evictAll() {
        if (delegate instanceof EvictablePermissionResolver evictable) {
            evictable.evictAll();
        }
    }

    @Override
    public void evictSubject(String subjectId) {
        if (delegate instanceof EvictablePermissionResolver evictable) {
            evictable.evictSubject(subjectId);
        }
    }
}
