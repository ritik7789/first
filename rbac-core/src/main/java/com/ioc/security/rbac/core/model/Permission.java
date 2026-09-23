package com.ioc.security.rbac.core.model;

/**
 * A permission in {@code resource:action} form, e.g. {@code booking:cancel}.
 *
 * @param code        normalised permission code
 * @param description optional human readable description
 */
public record Permission(String code, String description) {

    public Permission {
        code = Identifiers.permissionCode(code);
    }

    public static Permission of(String code) {
        return new Permission(code, null);
    }
}
