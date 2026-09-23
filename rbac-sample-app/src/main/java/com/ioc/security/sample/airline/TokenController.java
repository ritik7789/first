package com.ioc.security.sample.airline;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * DEMO ONLY: stands in for an identity provider (Keycloak, Okta, Azure AD, ...). Exchanges username/password for a
 * signed JWT carrying {@code preferred_username} and, for airline staff, an {@code airline} claim.
 */
@RestController
public class TokenController {

    /** Demo users and the airline (tenant) their token is bound to; empty = not bound to an airline. */
    static final Map<String, String> DEMO_AIRLINES = new LinkedHashMap<>();

    static {
        DEMO_AIRLINES.put("root", "");
        DEMO_AIRLINES.put("ops", "");
        DEMO_AIRLINES.put("rbac-admin", "");
        DEMO_AIRLINES.put("passenger", "");
        DEMO_AIRLINES.put("agent-sky", "SKY");
        DEMO_AIRLINES.put("supervisor-sky", "SKY");
        DEMO_AIRLINES.put("agent-blue", "BLUE");
    }

    public record TokenRequest(String username, String password) {
    }

    public record TokenResponse(String accessToken, String tokenType, long expiresIn) {
    }

    private final UserDetailsService users;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder encoder;
    private final Duration ttl;

    public TokenController(UserDetailsService users, PasswordEncoder passwordEncoder, JwtEncoder encoder,
                           @Value("${airline.jwt.ttl:1h}") Duration ttl) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.encoder = encoder;
        this.ttl = ttl;
    }

    @PostMapping("/auth/token")
    public ResponseEntity<TokenResponse> token(@RequestBody TokenRequest request) {
        UserDetails user;
        try {
            user = users.loadUserByUsername(request.username());
        } catch (UsernameNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (request.password() == null || !passwordEncoder.matches(request.password(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer("airline-sample")
                .subject(UUID.nameUUIDFromBytes(user.getUsername().getBytes()).toString())
                .claim("preferred_username", user.getUsername())
                .issuedAt(now)
                .expiresAt(now.plus(ttl));
        String airline = DEMO_AIRLINES.getOrDefault(user.getUsername(), "");
        if (!airline.isEmpty()) {
            claims.claim("airline", airline);
        }
        String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),
                claims.build())).getTokenValue();
        return ResponseEntity.ok(new TokenResponse(token, "Bearer", ttl.toSeconds()));
    }
}
