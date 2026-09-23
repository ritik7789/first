package com.ioc.security.rbac.spring.authority;

import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.spring.RbacService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Exposes RBAC roles and permissions as Spring Security {@link GrantedAuthority}s, so existing
 * {@code hasRole('ADMIN')} / {@code hasAuthority('booking:read')} checks keep working while an application migrates.
 *
 * <p>Authorities are computed at authentication time; for session based logins changes apply after the next login.
 * Checks made through {@link RbacService} and the RBAC annotations are always evaluated live.
 */
public class RbacAuthorityMapper {

    private final RbacService rbacService;
    private final String rolePrefix;
    private final String permissionPrefix;

    public RbacAuthorityMapper(RbacService rbacService, String rolePrefix, String permissionPrefix) {
        this.rbacService = rbacService;
        this.rolePrefix = rolePrefix == null ? "" : rolePrefix;
        this.permissionPrefix = permissionPrefix == null ? "" : permissionPrefix;
    }

    public Set<GrantedAuthority> authoritiesFor(String subjectId, String tenantId) {
        return toAuthorities(rbacService.permissionsOf(subjectId, tenantId));
    }

    public Set<GrantedAuthority> toAuthorities(EffectivePermissions effective) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        effective.roles().forEach(r -> authorities.add(new SimpleGrantedAuthority(rolePrefix + r)));
        effective.permissions().forEach(p -> authorities.add(new SimpleGrantedAuthority(permissionPrefix + p)));
        return authorities;
    }

    /**
     * Merges RBAC authorities into existing ones.
     */
    public Set<GrantedAuthority> merge(Collection<? extends GrantedAuthority> existing, String subjectId,
                                       String tenantId) {
        Set<GrantedAuthority> merged = new LinkedHashSet<>(existing);
        merged.addAll(authoritiesFor(subjectId, tenantId));
        return merged;
    }

    /**
     * Decorates a {@link UserDetailsService} (form login, HTTP basic, LDAP bridges, ...) so loaded users also carry
     * their global RBAC roles and permissions as authorities.
     */
    public UserDetailsService decorate(UserDetailsService delegate) {
        return username -> {
            UserDetails user = delegate.loadUserByUsername(username);
            return User.withUserDetails(user)
                    .authorities(merge(user.getAuthorities(), user.getUsername(), null))
                    .build();
        };
    }
}
