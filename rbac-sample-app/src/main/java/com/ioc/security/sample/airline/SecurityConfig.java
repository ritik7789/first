package com.ioc.security.sample.airline;

import com.ioc.security.rbac.spring.authority.RbacAuthorityMapper;
import com.ioc.security.rbac.spring.web.RbacUrlRules;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Authentication is entirely the application's concern (HTTP Basic with demo users here; JWT, OAuth2 login, LDAP,
 * ... work the same). RBAC only needs the authenticated user's name.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, RbacUrlRules rbacUrlRules) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.requestMatchers(HttpMethod.GET, "/actuator/health").permitAll())
                .authorizeHttpRequests(rbacUrlRules)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /**
     * Demo users. Decorating the UserDetailsService with the RBAC authority mapper also exposes RBAC roles as
     * ROLE_* authorities, so legacy {@code hasRole(...)} checks keep working during a migration.
     */
    @Bean
    UserDetailsService userDetailsService(RbacAuthorityMapper rbacAuthorityMapper) {
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        for (String name : new String[]{"root", "ops", "rbac-admin", "agent-sky", "agent-blue", "supervisor-sky",
                "passenger"}) {
            users.createUser(User.withUsername(name).password("{noop}password").roles().build());
        }
        return rbacAuthorityMapper.decorate(users);
    }
}
