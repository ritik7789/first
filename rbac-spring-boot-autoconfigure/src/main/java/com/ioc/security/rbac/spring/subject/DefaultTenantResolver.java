package com.ioc.security.rbac.spring.subject;

import org.springframework.security.core.Authentication;
import org.springframework.util.ClassUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Resolves the tenant from a token claim (if configured) and otherwise from an HTTP request header.
 *
 * <p>Taking the tenant from a header is safe: a subject only gains the roles assigned to it in that tenant (plus its
 * global roles), so choosing another tenant never grants more than was assigned there.
 */
public class DefaultTenantResolver implements TenantResolver {

    private static final boolean WEB_PRESENT = ClassUtils.isPresent(
            "org.springframework.web.context.request.RequestContextHolder", DefaultTenantResolver.class.getClassLoader())
            && ClassUtils.isPresent("jakarta.servlet.http.HttpServletRequest", DefaultTenantResolver.class.getClassLoader());

    private final String header;
    private final String claim;

    public DefaultTenantResolver(String header, String claim) {
        this.header = header;
        this.claim = claim;
    }

    @Override
    public String resolve(Authentication authentication) {
        String fromClaim = TokenAttributes.claim(authentication, claim);
        if (fromClaim != null && !fromClaim.isBlank()) {
            return fromClaim.trim();
        }
        if (WEB_PRESENT && header != null && !header.isBlank()) {
            return Web.header(header);
        }
        return null;
    }

    private static final class Web {

        static String header(String name) {
            RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
            if (attributes instanceof ServletRequestAttributes servlet) {
                String value = servlet.getRequest().getHeader(name);
                return value == null || value.isBlank() ? null : value.trim();
            }
            return null;
        }
    }
}
