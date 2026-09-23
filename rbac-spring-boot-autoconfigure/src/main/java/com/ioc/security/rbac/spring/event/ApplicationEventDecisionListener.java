package com.ioc.security.rbac.spring.event;

import com.ioc.security.rbac.spring.AccessDecision;
import com.ioc.security.rbac.spring.RbacDecisionListener;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Publishes {@link RbacAccessEvent}s for denied decisions, and for granted ones if configured.
 */
public class ApplicationEventDecisionListener implements RbacDecisionListener {

    private final ApplicationEventPublisher publisher;
    private final boolean includeGranted;

    public ApplicationEventDecisionListener(ApplicationEventPublisher publisher, boolean includeGranted) {
        this.publisher = publisher;
        this.includeGranted = includeGranted;
    }

    @Override
    public void onDecision(AccessDecision decision) {
        if (!decision.granted() || includeGranted) {
            publisher.publishEvent(new RbacAccessEvent(this, decision));
        }
    }
}
