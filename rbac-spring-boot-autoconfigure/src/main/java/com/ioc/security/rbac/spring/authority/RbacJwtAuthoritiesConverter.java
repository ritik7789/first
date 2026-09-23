package com.ioc.security.rbac.spring.authority;

import com.ioc.security.rbac.spring.subject.TenantResolver;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;

/**
 * JWT authorities converter adding RBAC roles and permissions to the scope authorities. Use with
 * {@code JwtAuthenticationConverter#setJwtGrantedAuthoritiesConverter}.
 */
public class RbacJwtAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final RbacAuthorityMapper mapper;
    private final String subjectClaim;
    private final TenantResolver tenantResolver;
    private final JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();

    public RbacJwtAuthoritiesConverter(RbacAuthorityMapper mapper, String subjectClaim, TenantResolver tenantResolver) {
        this.mapper = mapper;
        this.subjectClaim = subjectClaim == null || subjectClaim.isBlank() ? "sub" : subjectClaim;
        this.tenantResolver = tenantResolver;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        String subject = jwt.getClaimAsString(subjectClaim);
        Collection<GrantedAuthority> existing = scopes.convert(jwt);
        if (subject == null) {
            return existing;
        }
        return mapper.merge(existing, subject, tenantResolver.resolve(null));
    }
}
