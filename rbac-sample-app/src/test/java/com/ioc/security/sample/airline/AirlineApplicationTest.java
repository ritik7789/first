package com.ioc.security.sample.airline;

import com.ioc.security.rbac.test.WithRbacUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end: HTTP Basic authentication, JDBC store on H2 with Flyway schema, seed data, tenants, admin API.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AirlineApplicationTest {

    private static final String SKY = "SKY";
    private static final String BLUE = "BLUE";

    @Autowired
    MockMvc mvc;

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void rbacTablesAreCreatedAndSeeded() {
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM rbac_role", Integer.class)).isEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM rbac_subject_role", Integer.class)).isGreaterThanOrEqualTo(7);
    }

    @Test
    void passengerCanOnlyRead() throws Exception {
        mvc.perform(get("/api/flights").with(httpBasic("passenger", "password"))).andExpect(status().isOk());
        mvc.perform(post("/api/flights/SK101/cancel").with(httpBasic("passenger", "password")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/flights")).andExpect(status().isUnauthorized());
    }

    @Test
    void agentsWorkOnlyForTheirAirline() throws Exception {
        String booking = "{\"flight\":\"SK101\",\"passenger\":\"Asha\"}";
        mvc.perform(post("/api/bookings").header("X-Airline", SKY).contentType(MediaType.APPLICATION_JSON)
                        .content(booking).with(httpBasic("agent-sky", "password")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.airline").value(SKY));
        mvc.perform(post("/api/bookings").header("X-Airline", BLUE).contentType(MediaType.APPLICATION_JSON)
                        .content(booking).with(httpBasic("agent-sky", "password")))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/bookings").contentType(MediaType.APPLICATION_JSON)
                        .content(booking).with(httpBasic("agent-sky", "password")))
                .andExpect(status().isForbidden());
    }

    @Test
    void anyOfPermissionsOnService() throws Exception {
        mvc.perform(delete("/api/bookings/1").header("X-Airline", SKY).with(httpBasic("supervisor-sky", "password")))
                .andExpect(status().isOk());
        mvc.perform(delete("/api/bookings/1").with(httpBasic("passenger", "password")))
                .andExpect(status().isForbidden());
    }

    @Test
    void wildcardPermissionsAndUrlRules() throws Exception {
        mvc.perform(post("/api/flights/BJ202/cancel").with(httpBasic("ops", "password")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CANCELLED"));
        mvc.perform(get("/api/reports/revenue").with(httpBasic("ops", "password"))).andExpect(status().isOk());
        mvc.perform(get("/api/reports/revenue").with(httpBasic("passenger", "password")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/actuator/metrics").with(httpBasic("ops", "password"))).andExpect(status().isOk());
        mvc.perform(get("/actuator/metrics").with(httpBasic("passenger", "password"))).andExpect(status().isForbidden());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void spelAndLegacyRoleChecks() throws Exception {
        mvc.perform(get("/api/reports/load-factor").with(httpBasic("ops", "password"))).andExpect(status().isOk());
        mvc.perform(get("/api/reports/load-factor").with(httpBasic("agent-sky", "password")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/reports/legacy").with(httpBasic("ops", "password"))).andExpect(status().isOk());
        mvc.perform(get("/api/reports/legacy").with(httpBasic("passenger", "password")))
                .andExpect(status().isForbidden());
    }

    @Test
    void supervisorManagesAgentsOfItsAirlineThroughAdminApi() throws Exception {
        mvc.perform(post("/api/rbac/subjects/new-agent/assignments").header("X-Airline", SKY)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"BOOKING_AGENT\",\"tenantId\":\"SKY\"}")
                        .with(httpBasic("supervisor-sky", "password")))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/rbac/subjects/new-agent/assignments")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"BOOKING_AGENT\",\"tenantId\":\"BLUE\"}")
                        .with(httpBasic("supervisor-sky", "password")))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/rbac/subjects/new-agent/assignments").header("X-Airline", SKY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"OPS_MANAGER\",\"tenantId\":\"SKY\"}")
                        .with(httpBasic("supervisor-sky", "password")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/rbac/me").header("X-Airline", SKY).with(httpBasic("supervisor-sky", "password")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", hasItem("BOOKING_AGENT")));
    }

    @Test
    @WithRbacUser(permissions = "flight:create")
    void testSupportAnnotation() throws Exception {
        mvc.perform(post("/api/flights").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"number\":\"SK999\",\"from\":\"DEL\",\"to\":\"GOI\",\"status\":\"SCHEDULED\"}"))
                .andExpect(status().isCreated());
    }
}
