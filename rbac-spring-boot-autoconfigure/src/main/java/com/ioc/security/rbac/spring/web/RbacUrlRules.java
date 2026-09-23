package com.ioc.security.rbac.spring.web;

import com.ioc.security.rbac.autoconfigure.RbacProperties;
import com.ioc.security.rbac.spring.RbacService;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;
import java.util.function.Supplier;

/**
 * Applies the {@code rbac.url-rules} to a {@link HttpSecurity} chain. Add it <em>before</em> your own catch-all rule:
 *
 * <pre>{@code
 * http.authorizeHttpRequests(rbacUrlRules)
 *     .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
 * }</pre>
 * Rules are evaluated in declaration order; the first matching rule decides.
 */
public class RbacUrlRules implements
        Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> {

    private final List<RbacProperties.UrlRule> rules;
    private final RbacService rbacService;

    public RbacUrlRules(List<RbacProperties.UrlRule> rules, RbacService rbacService) {
        this.rules = List.copyOf(rules);
        this.rbacService = rbacService;
        for (RbacProperties.UrlRule rule : this.rules) {
            if (rule.getPatterns().isEmpty()) {
                throw new IllegalStateException("rbac.url-rules entries need at least one pattern");
            }
            if (rule.getPermissions().isEmpty() && rule.getRoles().isEmpty()) {
                throw new IllegalStateException("rbac.url-rules entry " + rule.getPatterns()
                        + " needs permissions and/or roles");
            }
        }
    }

    @Override
    public void customize(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        for (RbacProperties.UrlRule rule : rules) {
            String[] patterns = rule.getPatterns().toArray(String[]::new);
            AuthorizationManager<RequestAuthorizationContext> manager = manager(rule);
            if (rule.getMethods().isEmpty()) {
                registry.requestMatchers(patterns).access(manager);
            } else {
                for (String method : rule.getMethods()) {
                    registry.requestMatchers(HttpMethod.valueOf(method.toUpperCase()), patterns).access(manager);
                }
            }
        }
    }

    public List<RbacProperties.UrlRule> rules() {
        return rules;
    }

    private AuthorizationManager<RequestAuthorizationContext> manager(RbacProperties.UrlRule rule) {
        return new RuleAuthorizationManager(rule, rbacService);
    }

    private record RuleAuthorizationManager(RbacProperties.UrlRule rule, RbacService rbacService)
            implements AuthorizationManager<RequestAuthorizationContext> {

        @Override
        @SuppressWarnings("deprecation")
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
            Authentication auth = authentication.get();
            String source = context.getRequest().getMethod() + " " + context.getRequest().getRequestURI();
            boolean granted = true;
            if (!rule.getPermissions().isEmpty()) {
                granted = rbacService.hasPermissions(auth, rule.getPermissions(), rule.getLogical(), source);
            }
            if (granted && !rule.getRoles().isEmpty()) {
                granted = rbacService.hasRoles(auth, rule.getRoles(), rule.getLogical(), source);
            }
            return new AuthorizationDecision(granted);
        }
    }

}
