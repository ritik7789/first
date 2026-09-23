package com.ioc.security.rbac.spring.subject;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Uses the configured token claim ({@code rbac.subject.claim}) when the caller authenticated with an OAuth2 token,
 * otherwise {@link Authentication#getName()}.
 */
public class DefaultSubjectIdResolver implements SubjectIdResolver {

    private final String claim;

    public DefaultSubjectIdResolver(String claim) {
        this.claim = claim;
    }

    @Override
    public String resolve(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }
        String fromClaim = TokenAttributes.claim(authentication, claim);
        if (fromClaim != null && !fromClaim.isBlank()) {
            return fromClaim;
        }
        String name = authentication.getName();
        return name == null || name.isBlank() ? null : name;
    }
}
