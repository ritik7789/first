package com.ioc.security.rbac.core.model;

import com.ioc.security.rbac.core.RbacValidationException;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validation and normalisation rules for permission codes, role names, subject ids and tenant ids.
 *
 * <ul>
 *   <li>Permission codes are one or more {@code :}-separated segments, e.g. {@code booking:cancel} or
 *       {@code flight:schedule:update}. A segment may be the wildcard {@code *}. Codes are normalised to lower case.</li>
 *   <li>Role names consist of letters, digits, {@code _}, {@code -} and {@code .}; they are case sensitive.</li>
 * </ul>
 */
public final class Identifiers {

    public static final String WILDCARD = "*";
    public static final String SEGMENT_SEPARATOR = ":";

    private static final Pattern PERMISSION_SEGMENT = Pattern.compile("[a-z0-9_.\\-]+|\\*");
    private static final Pattern ROLE_NAME = Pattern.compile("[A-Za-z0-9_.\\-]{1,100}");
    private static final int MAX_PERMISSION_LENGTH = 150;
    private static final int MAX_SUBJECT_LENGTH = 255;
    private static final int MAX_TENANT_LENGTH = 100;

    private Identifiers() {
    }

    /**
     * Validates a permission code and returns its normalised (lower case, trimmed) form.
     */
    public static String permissionCode(String code) {
        if (code == null || code.isBlank()) {
            throw new RbacValidationException("Permission code must not be blank");
        }
        String normalised = code.trim().toLowerCase(Locale.ROOT);
        if (normalised.length() > MAX_PERMISSION_LENGTH) {
            throw new RbacValidationException("Permission code must be at most " + MAX_PERMISSION_LENGTH + " characters: " + code);
        }
        for (String segment : normalised.split(SEGMENT_SEPARATOR, -1)) {
            if (!PERMISSION_SEGMENT.matcher(segment).matches()) {
                throw new RbacValidationException("Invalid permission code '" + code
                        + "'. Expected segments like 'resource:action' using [a-z0-9_.-] or '*'");
            }
        }
        return normalised;
    }

    public static String roleName(String name) {
        if (name == null || !ROLE_NAME.matcher(name.trim()).matches()) {
            throw new RbacValidationException("Invalid role name '" + name
                    + "'. Use 1-100 characters from [A-Za-z0-9_.-]");
        }
        return name.trim();
    }

    public static String subjectId(String subjectId) {
        if (subjectId == null || subjectId.isBlank()) {
            throw new RbacValidationException("Subject id must not be blank");
        }
        if (subjectId.length() > MAX_SUBJECT_LENGTH) {
            throw new RbacValidationException("Subject id must be at most " + MAX_SUBJECT_LENGTH + " characters");
        }
        return subjectId;
    }

    /**
     * Validates an optional tenant id. {@code null} or blank means "global" (all tenants).
     */
    public static String tenantId(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            return null;
        }
        String trimmed = tenantId.trim();
        if (WILDCARD.equals(trimmed)) {
            throw new RbacValidationException("'*' is reserved and cannot be used as a tenant id");
        }
        if (trimmed.length() > MAX_TENANT_LENGTH) {
            throw new RbacValidationException("Tenant id must be at most " + MAX_TENANT_LENGTH + " characters");
        }
        return trimmed;
    }
}
