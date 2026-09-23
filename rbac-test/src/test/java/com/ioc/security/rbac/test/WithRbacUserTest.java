package com.ioc.security.rbac.test;

import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.annotation.RequiresPermission;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = WithRbacUserTest.BookingController.class, properties = {
        "rbac.seed.roles.PASSENGER.permissions=booking:read",
        "rbac.seed.roles.AGENT.parent=PASSENGER",
        "rbac.seed.roles.AGENT.permissions=booking:create",
})
@Import(WithRbacUserTest.BookingController.class)
class WithRbacUserTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    RbacService rbacService;

    @Test
    @WithRbacUser(permissions = "booking:read")
    void explicitPermissions() throws Exception {
        mvc.perform(get("/bookings")).andExpect(status().isOk());
        mvc.perform(get("/bookings/new")).andExpect(status().isForbidden());
    }

    @Test
    @WithRbacUser(value = "alice", roles = "AGENT")
    void rolesAreExpandedFromStore() throws Exception {
        assertThat(rbacService.currentPermissions().roles()).containsExactlyInAnyOrder("AGENT", "PASSENGER");
        assertThat(rbacService.currentSubjectId()).contains("alice");
        mvc.perform(get("/bookings")).andExpect(status().isOk());
        mvc.perform(get("/bookings/new")).andExpect(status().isOk());
    }

    @Test
    @WithRbacUser
    void noGrants() throws Exception {
        mvc.perform(get("/bookings")).andExpect(status().isForbidden());
    }

    @Test
    void anonymous() throws Exception {
        mvc.perform(get("/bookings")).andExpect(status().isUnauthorized());
    }

    @SpringBootApplication
    static class App {
    }

    @RestController
    static class BookingController {

        @GetMapping("/bookings")
        @RequiresPermission("booking:read")
        String list() {
            return "list";
        }

        @GetMapping("/bookings/new")
        @RequiresPermission("booking:create")
        String create() {
            return "new";
        }
    }
}
