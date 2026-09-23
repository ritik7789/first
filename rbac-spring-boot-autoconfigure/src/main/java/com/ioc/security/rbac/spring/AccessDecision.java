package com.ioc.security.rbac.spring;

import java.util.List;

/**
 * Outcome of one authorisation check, passed to {@link RbacDecisionListener}s for auditing and metrics.
 *
 * @param subjectId subject that was checked, {@code null} when unauthenticated
 * @param tenantId  tenant the check was made in
 * @param type      whether permissions or roles were checked
 * @param required  required permissions / roles
 * @param logical   how {@code required} was combined
 * @param granted   the decision
 * @param source    where the check came from (e.g. method signature, URL, "programmatic")
 */
public record AccessDecision(String subjectId, String tenantId, Type type, List<String> required, Logical logical,
                             boolean granted, String source) {

    public enum Type { PERMISSION, ROLE }
}
