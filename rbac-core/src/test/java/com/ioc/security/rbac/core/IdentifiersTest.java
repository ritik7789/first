package com.ioc.security.rbac.core;

import com.ioc.security.rbac.core.model.Identifiers;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdentifiersTest {

    @Test
    void normalisesPermissionCodes() {
        assertThat(Identifiers.permissionCode("  Booking:Cancel ")).isEqualTo("booking:cancel");
        assertThat(Identifiers.permissionCode("*")).isEqualTo("*");
        assertThat(Identifiers.permissionCode("flight:schedule-v2:update")).isEqualTo("flight:schedule-v2:update");
    }

    @Test
    void rejectsInvalidPermissionCodes() {
        assertThatThrownBy(() -> Identifiers.permissionCode("booking::read")).isInstanceOf(RbacValidationException.class);
        assertThatThrownBy(() -> Identifiers.permissionCode("booking:re*d")).isInstanceOf(RbacValidationException.class);
        assertThatThrownBy(() -> Identifiers.permissionCode("booking read")).isInstanceOf(RbacValidationException.class);
        assertThatThrownBy(() -> Identifiers.permissionCode("")).isInstanceOf(RbacValidationException.class);
    }

    @Test
    void validatesRoleNamesAndTenants() {
        assertThat(Identifiers.roleName("OPS_MANAGER")).isEqualTo("OPS_MANAGER");
        assertThatThrownBy(() -> Identifiers.roleName("ops manager")).isInstanceOf(RbacValidationException.class);
        assertThat(Identifiers.tenantId(" ")).isNull();
        assertThatThrownBy(() -> Identifiers.tenantId("*")).isInstanceOf(RbacValidationException.class);
    }
}
