package com.ioc.security.sample.airline;

import com.ioc.security.rbac.test.WithRbacUser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end with real signed JWTs: token endpoint, resource server validation, RBAC from JWT claims, JDBC store on
 * H2 with the Flyway schema, seed data, airline tenants and the admin API.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AirlineApplicationTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    JwtEncoder encoder;

    // ---------------------------------------------------------------- helpers

    private String token(String username) throws Exception {
        String body = mvc.perform(post("/auth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.accessToken");
    }

    private MockHttpServletRequestBuilder as(String username, MockHttpServletRequestBuilder request) throws Exception {
        return request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token(username));
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder request, String body) {
        return request.contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String sign(JwtEncoder encoder, JwtClaimsSet claims) {
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();
    }

    // ---------------------------------------------------------------- token endpoint & token validation

    @Test
    void tokenEndpointIssuesSignedJwtWithRbacClaims() throws Exception {
        mvc.perform(json(post("/auth/token"), "{\"username\":\"agent-sky\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(3600));
        String[] parts = token("agent-sky").split("\\.");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payload).contains("\"preferred_username\":\"agent-sky\"", "\"airline\":\"SKY\"");

        mvc.perform(json(post("/auth/token"), "{\"username\":\"agent-sky\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(json(post("/auth/token"), "{\"username\":\"nobody\",\"password\":\"password\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidTokensAreRejected() throws Exception {
        mvc.perform(get("/api/flights")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/flights").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized());

        String valid = token("ops");
        String tampered = valid.substring(0, valid.length() - 4) + (valid.endsWith("AAAA") ? "BBBB" : "AAAA");
        mvc.perform(get("/api/flights").header(HttpHeaders.AUTHORIZATION, "Bearer " + tampered))
                .andExpect(status().isUnauthorized());

        JwtEncoder otherKey = new NimbusJwtEncoder(new ImmutableSecret<>(new SecretKeySpec(
                "another-secret-that-is-at-least-32-bytes".getBytes(StandardCharsets.UTF_8), "HmacSHA256")));
        String forged = sign(otherKey, JwtClaimsSet.builder().claim("preferred_username", "root")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(600)).build());
        mvc.perform(get("/api/flights").header(HttpHeaders.AUTHORIZATION, "Bearer " + forged))
                .andExpect(status().isUnauthorized());

        String expired = sign(encoder, JwtClaimsSet.builder().claim("preferred_username", "ops")
                .issuedAt(Instant.now().minusSeconds(7200)).expiresAt(Instant.now().minusSeconds(3600)).build());
        mvc.perform(get("/api/flights").header(HttpHeaders.AUTHORIZATION, "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void apiIsStateless() throws Exception {
        mvc.perform(as("passenger", get("/api/flights")))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    // ---------------------------------------------------------------- RBAC driven by JWT claims

    @Test
    void rbacTablesAreCreatedAndSeeded() {
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM rbac_role", Integer.class)).isEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM rbac_subject_role", Integer.class))
                .isGreaterThanOrEqualTo(7);
    }

    @Test
    void permissionsFromPreferredUsername() throws Exception {
        mvc.perform(as("passenger", get("/api/flights"))).andExpect(status().isOk());
        mvc.perform(as("passenger", post("/api/flights/SK101/cancel"))).andExpect(status().isForbidden());
        mvc.perform(as("ops", post("/api/flights/BJ202/cancel")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CANCELLED"));
    }

    @Test
    void airlineClaimBindsStaffToTheirAirline() throws Exception {
        String booking = "{\"flight\":\"SK101\",\"passenger\":\"Asha\"}";
        mvc.perform(json(as("agent-sky", post("/api/bookings")), booking))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.airline").value("SKY"));
        // the claim wins over the header: a SKY agent cannot act for BLUE by sending X-Airline: BLUE
        mvc.perform(json(as("agent-sky", post("/api/bookings")), booking).header("X-Airline", "BLUE"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.airline").value("SKY"));
        mvc.perform(json(as("agent-blue", post("/api/bookings")), booking))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.airline").value("BLUE"));
        // a token without airline claim and with only global roles cannot book
        mvc.perform(json(as("passenger", post("/api/bookings")), booking).header("X-Airline", "SKY"))
                .andExpect(status().isForbidden());
    }

    @Test
    void anyOfPermissionsOnService() throws Exception {
        mvc.perform(as("supervisor-sky", delete("/api/bookings/1"))).andExpect(status().isOk());
        mvc.perform(as("passenger", delete("/api/bookings/1"))).andExpect(status().isForbidden());
    }

    @Test
    void urlRulesAndActuator() throws Exception {
        mvc.perform(as("ops", get("/api/reports/revenue"))).andExpect(status().isOk());
        mvc.perform(as("passenger", get("/api/reports/revenue"))).andExpect(status().isForbidden());
        mvc.perform(as("ops", get("/actuator/metrics"))).andExpect(status().isOk());
        mvc.perform(as("passenger", get("/actuator/metrics"))).andExpect(status().isForbidden());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void spelAndLegacyRoleChecksThroughJwtAuthoritiesConverter() throws Exception {
        mvc.perform(as("ops", get("/api/reports/load-factor"))).andExpect(status().isOk());
        mvc.perform(as("agent-sky", get("/api/reports/load-factor"))).andExpect(status().isForbidden());
        // hasRole('OPS_MANAGER') works because RbacJwtAuthoritiesConverter adds ROLE_OPS_MANAGER
        mvc.perform(as("ops", get("/api/reports/legacy"))).andExpect(status().isOk());
        mvc.perform(as("passenger", get("/api/reports/legacy"))).andExpect(status().isForbidden());
    }

    @Test
    void roleChangesApplyToExistingTokensImmediately() throws Exception {
        String lateJoiner = token("passenger");
        MockHttpServletRequestBuilder createFlight = json(post("/api/flights"),
                "{\"number\":\"SK777\",\"from\":\"DEL\",\"to\":\"DXB\",\"status\":\"SCHEDULED\"}");

        mvc.perform(get("/api/reports/load-factor").header(HttpHeaders.AUTHORIZATION, "Bearer " + lateJoiner))
                .andExpect(status().isForbidden());
        mvc.perform(json(as("root", post("/api/rbac/subjects/passenger/assignments")),
                        "{\"role\":\"OPS_MANAGER\"}"))
                .andExpect(status().isCreated());
        // same token, no re-login
        mvc.perform(get("/api/reports/load-factor").header(HttpHeaders.AUTHORIZATION, "Bearer " + lateJoiner))
                .andExpect(status().isOk());
        mvc.perform(createFlight.header(HttpHeaders.AUTHORIZATION, "Bearer " + lateJoiner))
                .andExpect(status().isCreated());

        mvc.perform(as("root", delete("/api/rbac/subjects/passenger/assignments/OPS_MANAGER")))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/reports/load-factor").header(HttpHeaders.AUTHORIZATION, "Bearer " + lateJoiner))
                .andExpect(status().isForbidden());
    }

    @Test
    void supervisorManagesAgentsOfItsAirlineThroughAdminApi() throws Exception {
        mvc.perform(json(as("supervisor-sky", post("/api/rbac/subjects/new-agent/assignments")),
                        "{\"role\":\"BOOKING_AGENT\",\"tenantId\":\"SKY\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.grantedBy").value("supervisor-sky"));
        mvc.perform(json(as("supervisor-sky", post("/api/rbac/subjects/new-agent/assignments")),
                        "{\"role\":\"BOOKING_AGENT\",\"tenantId\":\"BLUE\"}"))
                .andExpect(status().isForbidden());
        mvc.perform(json(as("supervisor-sky", post("/api/rbac/subjects/new-agent/assignments")),
                        "{\"role\":\"OPS_MANAGER\",\"tenantId\":\"SKY\"}"))
                .andExpect(status().isForbidden());
        mvc.perform(as("supervisor-sky", get("/api/rbac/me")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subjectId").value("supervisor-sky"))
                .andExpect(jsonPath("$.tenantId").value("SKY"))
                .andExpect(jsonPath("$.roles", hasItem("BOOKING_AGENT")));
    }

    @Test
    @WithRbacUser(permissions = "flight:create")
    void testSupportAnnotationStillWorksWithoutToken() throws Exception {
        mvc.perform(json(post("/api/flights"),
                        "{\"number\":\"SK999\",\"from\":\"DEL\",\"to\":\"GOI\",\"status\":\"SCHEDULED\"}"))
                .andExpect(status().isCreated());
    }
}
