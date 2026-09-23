package com.ioc.security.rbac.admin;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = AdminTestApplication.class, properties = {
        "rbac.admin-api.enabled=true",
        "rbac.super-admin-role=SUPER_ADMIN",
        "rbac.multi-tenancy.enabled=true",
        "rbac.seed.roles.SUPER_ADMIN.description=All",
        "rbac.seed.roles.RBAC_ADMIN.permissions=rbac:read,rbac:manage,booking:read",
        "rbac.seed.roles.RBAC_VIEWER.permissions=rbac:read",
        "rbac.seed.roles.AGENT.permissions=booking:read,booking:create",
        "rbac.seed.roles.TENANT_ADMIN.permissions=rbac:read,rbac:manage,booking:read,booking:create",
        "rbac.seed.assignments[0].subject=root",
        "rbac.seed.assignments[0].role=SUPER_ADMIN",
        "rbac.seed.assignments[1].subject=admin",
        "rbac.seed.assignments[1].role=RBAC_ADMIN",
        "rbac.seed.assignments[2].subject=viewer",
        "rbac.seed.assignments[2].role=RBAC_VIEWER",
        "rbac.seed.assignments[3].subject=ai-admin",
        "rbac.seed.assignments[3].role=TENANT_ADMIN",
        "rbac.seed.assignments[3].tenant=AI",
})
@AutoConfigureMockMvc
@DirtiesContext
class RbacAdminControllerTest {

    @Autowired
    MockMvc mvc;

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder builder, String body) {
        return builder.contentType(MediaType.APPLICATION_JSON).content(body);
    }

    @Test
    void meReturnsEffectivePermissions() throws Exception {
        mvc.perform(get("/rbac/me").with(user("admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subjectId").value("admin"))
                .andExpect(jsonPath("$.roles[0]").value("RBAC_ADMIN"))
                .andExpect(jsonPath("$.permissions", containsInAnyOrder("rbac:read", "rbac:manage", "booking:read")))
                .andExpect(jsonPath("$.superAdmin").value(false));
        mvc.perform(get("/rbac/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void readRequiresReadPermission() throws Exception {
        mvc.perform(get("/rbac/roles").with(user("viewer"))).andExpect(status().isOk())
                .andExpect(jsonPath("$[*].name", hasItem("AGENT")));
        mvc.perform(get("/rbac/roles").with(user("nobody"))).andExpect(status().isForbidden());
    }

    @Test
    void manageRequiresManagePermission() throws Exception {
        mvc.perform(json(post("/rbac/permissions"), "{\"code\":\"report:read\"}").with(user("viewer")))
                .andExpect(status().isForbidden());
        mvc.perform(json(post("/rbac/permissions"), "{\"code\":\"report:read\",\"description\":\"Reports\"}")
                        .with(user("root")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").value("report:read"));
    }

    @Test
    void roleLifecycleWithProblemDetails() throws Exception {
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"CHECKIN\",\"permissions\":[\"booking:read\"]}")
                        .with(user("admin")))
                .andExpect(status().isCreated());
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"CHECKIN\"}").with(user("admin")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
        mvc.perform(json(put("/rbac/roles/CHECKIN"), "{\"description\":\"Check-in\",\"parent\":\"CHECKIN\"}")
                        .with(user("admin")))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/rbac/roles/MISSING").with(user("admin"))).andExpect(status().isNotFound());
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"bad name\"}").with(user("admin")))
                .andExpect(status().isBadRequest());
        mvc.perform(delete("/rbac/roles/CHECKIN").with(user("admin"))).andExpect(status().isNoContent());
    }

    @Test
    void cannotGrantPermissionsNotHeld() throws Exception {
        // admin holds booking:read but not booking:create
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"SNEAKY\",\"permissions\":[\"booking:create\"]}")
                        .with(user("admin")))
                .andExpect(status().isForbidden());
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"SNEAKY2\",\"permissions\":[\"*\"]}")
                        .with(user("admin")))
                .andExpect(status().isForbidden());
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"SNEAKY3\",\"parent\":\"AGENT\"}").with(user("admin")))
                .andExpect(status().isForbidden());
        mvc.perform(json(post("/rbac/subjects/admin/assignments"), "{\"role\":\"AGENT\"}").with(user("admin")))
                .andExpect(status().isForbidden());
        mvc.perform(json(post("/rbac/subjects/admin/assignments"), "{\"role\":\"SUPER_ADMIN\"}").with(user("admin")))
                .andExpect(status().isForbidden());
        // a role inheriting from the super-admin role is just as powerful
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"SNEAKY4\",\"parent\":\"SUPER_ADMIN\"}")
                        .with(user("admin")))
                .andExpect(status().isForbidden());
    }

    @Test
    void tenantAdminManagesOnlyItsTenant() throws Exception {
        mvc.perform(json(post("/rbac/subjects/agent-1/assignments"), "{\"role\":\"AGENT\",\"tenantId\":\"AI\"}")
                        .with(user("ai-admin")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.grantedBy").value("ai-admin"));
        mvc.perform(json(post("/rbac/subjects/agent-1/assignments"), "{\"role\":\"AGENT\",\"tenantId\":\"6E\"}")
                        .with(user("ai-admin")))
                .andExpect(status().isForbidden());
        mvc.perform(json(post("/rbac/subjects/agent-1/assignments"), "{\"role\":\"AGENT\"}")
                        .with(user("ai-admin")))
                .andExpect(status().isForbidden());
        mvc.perform(json(post("/rbac/roles"), "{\"name\":\"X\"}").with(user("ai-admin")))
                .andExpect(status().isForbidden());

        mvc.perform(get("/rbac/subjects/agent-1/permissions").param("tenantId", "AI").with(user("root")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions", containsInAnyOrder("booking:read", "booking:create")));

        mvc.perform(delete("/rbac/subjects/agent-1/assignments/AGENT").param("tenantId", "AI").with(user("ai-admin")))
                .andExpect(status().isNoContent());
        mvc.perform(delete("/rbac/subjects/agent-1/assignments/AGENT").param("tenantId", "AI").with(user("ai-admin")))
                .andExpect(status().isNotFound());
    }

    @Test
    void superAdminCanDoEverything() throws Exception {
        mvc.perform(json(post("/rbac/subjects/new-agent/assignments"),
                        "{\"role\":\"AGENT\",\"expiresAt\":\"2099-01-01T00:00:00Z\"}").with(user("root")))
                .andExpect(status().isCreated());
        mvc.perform(get("/rbac/subjects/new-agent/assignments").with(user("root")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].roleName").value("AGENT"))
                .andExpect(jsonPath("$[0].expiresAt").value("2099-01-01T00:00:00Z"));
    }
}
