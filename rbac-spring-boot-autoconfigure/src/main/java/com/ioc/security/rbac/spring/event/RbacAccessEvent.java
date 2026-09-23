package com.ioc.security.rbac.spring.event;

import com.ioc.security.rbac.spring.AccessDecision;
import org.springframework.context.ApplicationEvent;

/**
 * Published for denied (and optionally granted) access decisions when {@code rbac.audit.enabled=true}.
 */
public class RbacAccessEvent extends ApplicationEvent {

    private final AccessDecision decision;

    public RbacAccessEvent(Object source, AccessDecision decision) {
        super(source);
        this.decision = decision;
    }

    public AccessDecision getDecision() {
        return decision;
    }
}
