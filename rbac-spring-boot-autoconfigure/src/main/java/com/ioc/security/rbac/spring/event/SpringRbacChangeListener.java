package com.ioc.security.rbac.spring.event;

import com.ioc.security.rbac.core.spi.EvictablePermissionResolver;
import com.ioc.security.rbac.core.spi.RbacChangeListener;
import com.ioc.security.rbac.spring.subject.SubjectIdResolver;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Evicts the local permission cache and publishes {@link RbacDataChangedEvent} after every data change.
 */
public class SpringRbacChangeListener implements RbacChangeListener {

    private final ApplicationEventPublisher publisher;
    private final EvictablePermissionResolver cache;
    private final SubjectIdResolver subjectIdResolver;

    public SpringRbacChangeListener(ApplicationEventPublisher publisher, EvictablePermissionResolver cache,
                                    SubjectIdResolver subjectIdResolver) {
        this.publisher = publisher;
        this.cache = cache;
        this.subjectIdResolver = subjectIdResolver;
    }

    @Override
    public void onChange(ChangeType type, String target, String detail) {
        if (cache != null) {
            if (type == ChangeType.ROLE_ASSIGNED || type == ChangeType.ROLE_REVOKED) {
                cache.evictSubject(target);
            } else {
                cache.evictAll();
            }
        }
        String actor = subjectIdResolver.resolve(SecurityContextHolder.getContext().getAuthentication());
        publisher.publishEvent(new RbacDataChangedEvent(this, type, target, detail, actor));
    }
}
