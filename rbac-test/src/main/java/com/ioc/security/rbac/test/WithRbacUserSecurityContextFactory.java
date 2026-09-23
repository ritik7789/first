package com.ioc.security.rbac.test;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.Set;

/**
 * Creates the security context for {@link WithRbacUser}.
 */
public class WithRbacUserSecurityContextFactory implements WithSecurityContextFactory<WithRbacUser> {

    @Override
    public SecurityContext createSecurityContext(WithRbacUser annotation) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new RbacTestAuthentication(annotation.value(), Set.of(annotation.roles()),
                Set.of(annotation.permissions())));
        return context;
    }
}
