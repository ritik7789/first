package com.ioc.security.rbac.spring.event;

import com.ioc.security.rbac.core.spi.RbacChangeListener.ChangeType;
import org.springframework.context.ApplicationEvent;

/**
 * Published after roles, permissions or assignments changed. Listen to it to propagate cache invalidation to other
 * nodes (e.g. via Redis pub/sub or Kafka) or to forward audit records.
 */
public class RbacDataChangedEvent extends ApplicationEvent {

    private final ChangeType changeType;
    private final String target;
    private final String detail;
    private final String actor;

    public RbacDataChangedEvent(Object source, ChangeType changeType, String target, String detail, String actor) {
        super(source);
        this.changeType = changeType;
        this.target = target;
        this.detail = detail;
        this.actor = actor;
    }

    public ChangeType getChangeType() {
        return changeType;
    }

    public String getTarget() {
        return target;
    }

    public String getDetail() {
        return detail;
    }

    /** Subject that made the change, or {@code null} for system changes (seeding). */
    public String getActor() {
        return actor;
    }

    @Override
    public String toString() {
        return "RbacDataChangedEvent[" + changeType + " " + target + (detail == null ? "" : " (" + detail + ")")
                + " by " + (actor == null ? "system" : actor) + "]";
    }
}
