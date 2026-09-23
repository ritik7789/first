package com.ioc.security.rbac.core.engine;

import com.ioc.security.rbac.core.model.Identifiers;
import com.ioc.security.rbac.core.spi.PermissionMatcher;

/**
 * Segment based wildcard matching.
 *
 * <ul>
 *   <li>{@code booking:read} implies only {@code booking:read}</li>
 *   <li>{@code *} in the middle matches exactly one segment: {@code *:read} implies {@code booking:read}</li>
 *   <li>{@code *} as the last segment matches all remaining segments: {@code booking:*} implies
 *       {@code booking:read} and {@code booking:seat:assign}; {@code *} alone implies everything</li>
 * </ul>
 * Comparison is case-insensitive.
 */
public class WildcardPermissionMatcher implements PermissionMatcher {

    @Override
    public boolean implies(String granted, String required) {
        if (granted == null || required == null) {
            return false;
        }
        String[] g = granted.split(Identifiers.SEGMENT_SEPARATOR, -1);
        String[] r = required.split(Identifiers.SEGMENT_SEPARATOR, -1);
        for (int i = 0; i < g.length; i++) {
            boolean last = i == g.length - 1;
            if (last && Identifiers.WILDCARD.equals(g[i])) {
                return true;
            }
            if (i >= r.length) {
                return false;
            }
            if (!Identifiers.WILDCARD.equals(g[i]) && !g[i].equalsIgnoreCase(r[i])) {
                return false;
            }
        }
        return g.length == r.length;
    }
}
