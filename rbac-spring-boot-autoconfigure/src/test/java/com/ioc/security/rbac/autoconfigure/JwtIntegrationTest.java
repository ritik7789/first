package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.core.engine.AccessEvaluator;
import com.ioc.security.rbac.core.engine.HierarchicalPermissionResolver;
import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.engine.WildcardPermissionMatcher;
import com.ioc.security.rbac.core.model.Role;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.core.store.InMemoryRbacStore;
import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.authority.RbacAuthorityMapper;
import com.ioc.security.rbac.spring.authority.RbacJwtAuthoritiesConverter;
import com.ioc.security.rbac.spring.subject.DefaultSubjectIdResolver;
import com.ioc.security.rbac.spring.subject.DefaultTenantResolver;
import com.ioc.security.rbac.spring.subject.TenantResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Subject and tenant resolution from JWT claims, and the JWT authorities converter.
 */
class JwtIntegrationTest {

    private final InMemoryRbacStore store = new InMemoryRbacStore();
    private RbacService rbac;
    private RbacAuthorityMapper mapper;
    private final DefaultTenantResolver tenantResolver = new DefaultTenantResolver("X-Airline", "airline");

    @BeforeEach
    void setUp() {
        RbacAdministration admin = new RbacAdministration(store);
        admin.createRole(Role.of("AGENT", "booking:create"), true);
        admin.createRole(Role.of("PASSENGER", "booking:read"), true);
        admin.assignRole(RoleAssignment.global("alice", "PASSENGER"));
        admin.assignRole(RoleAssignment.forTenant("alice", "AGENT", "SKY"));
        rbac = new RbacService(new HierarchicalPermissionResolver(store),
                new AccessEvaluator(new WildcardPermissionMatcher(), null),
                new DefaultSubjectIdResolver("preferred_username"), tenantResolver, List.of());
        mapper = new RbacAuthorityMapper(rbac, "ROLE_", "");
    }

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "HS256").subject("7f3c-uuid");
        claims.forEach(builder::claim);
        return builder.build();
    }

    private static void header(String name, String value) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(name, value);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Test
    void subjectComesFromConfiguredClaimNotFromSub() {
        JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt(Map.of("preferred_username", "alice")), List.of());
        assertThat(rbac.permissionsOf(auth).subjectId()).isEqualTo("alice");
        assertThat(rbac.hasPermissions(auth, List.of("booking:read"), com.ioc.security.rbac.spring.Logical.ALL, "t"))
                .isTrue();
    }

    @Test
    void tenantClaimWinsOverHeader() {
        header("X-Airline", "BLUE");
        JwtAuthenticationToken auth = new JwtAuthenticationToken(
                jwt(Map.of("preferred_username", "alice", "airline", "SKY")), List.of());
        assertThat(rbac.permissionsOf(auth).tenantId()).isEqualTo("SKY");
        assertThat(rbac.permissionsOf(auth).permissions()).contains("booking:create");
    }

    @Test
    void headerIsUsedWhenTokenHasNoTenantClaim() {
        header("X-Airline", "SKY");
        JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt(Map.of("preferred_username", "alice")), List.of());
        assertThat(rbac.permissionsOf(auth).tenantId()).isEqualTo("SKY");
    }

    @Test
    void authoritiesConverterAddsRolesPermissionsAndScopes() {
        RbacJwtAuthoritiesConverter converter =
                new RbacJwtAuthoritiesConverter(mapper, "preferred_username", "airline", TenantResolver.NONE);

        List<String> inSky = names(converter.convert(
                jwt(Map.of("preferred_username", "alice", "airline", "SKY", "scope", "profile"))));
        assertThat(inSky).contains("SCOPE_profile", "ROLE_PASSENGER", "ROLE_AGENT", "booking:read", "booking:create");

        List<String> global = names(converter.convert(jwt(Map.of("preferred_username", "alice"))));
        assertThat(global).contains("ROLE_PASSENGER").doesNotContain("ROLE_AGENT");

        List<String> unknownUser = names(converter.convert(jwt(Map.of("scope", "profile"))));
        assertThat(unknownUser).containsExactly("SCOPE_profile");
    }

    private static List<String> names(java.util.Collection<GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }
}
