package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.core.engine.RbacAdministration;
import com.ioc.security.rbac.core.model.RoleAssignment;
import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.event.RbacAccessEvent;
import com.ioc.security.rbac.spring.event.RbacDataChangedEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {TestApplication.class, RbacAutoConfigurationIntegrationTest.Events.class}, properties = {
        "rbac.super-admin-role=SUPER_ADMIN",
        "rbac.multi-tenancy.enabled=true",
        "rbac.seed.permissions[flight\\:read]=Read flights",
        "rbac.seed.roles.SUPERVISOR.parent=VIEWER",
        "rbac.seed.roles.SUPERVISOR.permissions=flight:cancel",
        "rbac.seed.roles.VIEWER.permissions=flight:read",
        "rbac.seed.roles.AUDITOR.permissions=audit:read",
        "rbac.seed.roles.SUPER_ADMIN.description=Everything",
        "rbac.seed.assignments[0].subject=viewer",
        "rbac.seed.assignments[0].role=VIEWER",
        "rbac.seed.assignments[1].subject=supervisor",
        "rbac.seed.assignments[1].role=SUPERVISOR",
        "rbac.seed.assignments[2].subject=tenant-user",
        "rbac.seed.assignments[2].role=SUPERVISOR",
        "rbac.seed.assignments[2].tenant=AI",
        "rbac.seed.assignments[3].subject=root",
        "rbac.seed.assignments[3].role=SUPER_ADMIN",
        "rbac.seed.assignments[4].subject=auditor",
        "rbac.seed.assignments[4].role=AUDITOR",
        "rbac.url-rules[0].pattern=/flights/url-rule",
        "rbac.url-rules[0].methods=GET",
        "rbac.url-rules[0].permissions=audit:read",
})
@AutoConfigureMockMvc
class RbacAutoConfigurationIntegrationTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    RbacService rbacService;

    @Autowired
    RbacAdministration administration;

    @Autowired
    Events events;

    @Test
    void methodAnnotationOnController() throws Exception {
        mvc.perform(get("/flights").with(user("viewer"))).andExpect(status().isOk());
        mvc.perform(get("/flights").with(user("stranger"))).andExpect(status().isForbidden());
        mvc.perform(get("/flights")).andExpect(status().isUnauthorized());
    }

    @Test
    void classAndMethodAnnotationsOnServiceAreBothRequired() throws Exception {
        mvc.perform(post("/flights/AI101/cancel").with(user("viewer"))).andExpect(status().isForbidden());
        mvc.perform(post("/flights/AI101/cancel").with(user("supervisor")))
                .andExpect(status().isOk())
                .andExpect(content().string("cancelled AI101"));
    }

    @Test
    void logicalAnyAndRoles() throws Exception {
        mvc.perform(get("/flights/any").with(user("viewer"))).andExpect(status().isOk());
        mvc.perform(get("/flights/supervisor").with(user("viewer"))).andExpect(status().isForbidden());
        mvc.perform(get("/flights/supervisor").with(user("supervisor"))).andExpect(status().isOk());
    }

    @Test
    void spelBeanPermissionEvaluatorAndProgrammaticChecks() throws Exception {
        for (String path : List.of("/flights/spel", "/flights/evaluator/1", "/flights/programmatic")) {
            mvc.perform(get(path).with(user("viewer"))).andExpect(status().isOk());
            mvc.perform(get(path).with(user("auditor"))).andExpect(status().isForbidden());
        }
    }

    @Test
    void urlRules() throws Exception {
        mvc.perform(get("/flights/url-rule").with(user("auditor"))).andExpect(status().isOk());
        mvc.perform(get("/flights/url-rule").with(user("viewer"))).andExpect(status().isForbidden());
    }

    @Test
    void tenantScopedAssignments() throws Exception {
        mvc.perform(post("/flights/X1/cancel").with(user("tenant-user")).header("X-Tenant-Id", "AI"))
                .andExpect(status().isOk());
        mvc.perform(post("/flights/X1/cancel").with(user("tenant-user")).header("X-Tenant-Id", "6E"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/flights/X1/cancel").with(user("tenant-user"))).andExpect(status().isForbidden());
    }

    @Test
    void superAdminBypassesChecks() throws Exception {
        mvc.perform(get("/flights/url-rule").with(user("root"))).andExpect(status().isOk());
        mvc.perform(get("/flights/supervisor").with(user("root"))).andExpect(status().isOk());
    }

    @Test
    void existingAuthoritiesAreNotEnoughWithoutRbacGrant() throws Exception {
        mvc.perform(get("/flights").with(user("stranger").roles("ADMIN").authorities(() -> "flight:read")))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser("late-joiner")
    void changesAreVisibleImmediatelyThroughCacheEviction() {
        assertThat(rbacService.hasPermission("flight:read")).isFalse();
        administration.assignRole(RoleAssignment.global("late-joiner", "VIEWER"));
        assertThat(rbacService.hasPermission("flight:read")).isTrue();
        administration.revokeRole("late-joiner", "VIEWER", null);
        assertThat(rbacService.hasPermission("flight:read")).isFalse();

        assertThat(events.received).anySatisfy(e -> assertThat(e).isInstanceOf(RbacDataChangedEvent.class));
        assertThat(events.received).anySatisfy(e -> assertThat(e).isInstanceOf(RbacAccessEvent.class));
    }

    @TestConfiguration
    static class Events {

        final List<ApplicationEvent> received = new CopyOnWriteArrayList<>();

        @Bean
        ApplicationListener<ApplicationEvent> rbacEventCollector() {
            return event -> {
                if (event instanceof RbacAccessEvent || event instanceof RbacDataChangedEvent) {
                    received.add(event);
                }
            };
        }
    }
}
