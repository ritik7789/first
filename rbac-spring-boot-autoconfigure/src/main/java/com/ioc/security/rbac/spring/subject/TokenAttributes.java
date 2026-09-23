package com.ioc.security.rbac.spring.subject;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.ClassUtils;

import java.util.Map;

/**
 * Reads claims from OAuth2 resource server authentications (JWT or opaque token) without requiring the OAuth2
 * modules on the classpath.
 */
final class TokenAttributes {

    private static final boolean RESOURCE_SERVER_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken",
            TokenAttributes.class.getClassLoader());

    private TokenAttributes() {
    }

    static String claim(Authentication authentication, String claim) {
        if (claim == null || claim.isBlank() || authentication == null || !RESOURCE_SERVER_PRESENT) {
            return null;
        }
        return OAuth2.claim(authentication, claim);
    }

    private static final class OAuth2 {

        static String claim(Authentication authentication, String claim) {
            Map<String, Object> attributes = null;
            if (authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> token) {
                attributes = token.getTokenAttributes();
            } else if (authentication.getPrincipal() instanceof OAuth2AuthenticatedPrincipal principal) {
                attributes = principal.getAttributes();
            }
            Object value = attributes == null ? null : attributes.get(claim);
            return value == null ? null : value.toString();
        }
    }
}
