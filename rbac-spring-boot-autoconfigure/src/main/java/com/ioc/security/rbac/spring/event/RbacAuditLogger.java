package com.ioc.security.rbac.spring.event;

import com.ioc.security.rbac.spring.AccessDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;

/**
 * Writes RBAC audit events to the {@code rbac.audit} logger. Replace or complement with your own listeners to ship
 * audit records elsewhere.
 */
public class RbacAuditLogger {

    private static final Logger log = LoggerFactory.getLogger("rbac.audit");

    @EventListener
    public void onAccess(RbacAccessEvent event) {
        AccessDecision d = event.getDecision();
        if (d.granted()) {
            log.debug("GRANTED subject={} tenant={} {} {} {} at {}", d.subjectId(), d.tenantId(), d.logical(),
                    d.type(), d.required(), d.source());
        } else {
            log.info("DENIED subject={} tenant={} {} {} {} at {}", d.subjectId(), d.tenantId(), d.logical(),
                    d.type(), d.required(), d.source());
        }
    }

    @EventListener
    public void onChange(RbacDataChangedEvent event) {
        log.info("CHANGED {} target={} detail={} actor={}", event.getChangeType(), event.getTarget(),
                event.getDetail(), event.getActor() == null ? "system" : event.getActor());
    }
}
