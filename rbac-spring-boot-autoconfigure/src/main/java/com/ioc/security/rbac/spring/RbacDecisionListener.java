package com.ioc.security.rbac.spring;

/**
 * Callback invoked for every access decision made by {@link RbacService}. Implementations must be fast and must not
 * throw; register them as beans.
 */
@FunctionalInterface
public interface RbacDecisionListener {

    void onDecision(AccessDecision decision);
}
