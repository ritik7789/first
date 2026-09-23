package com.ioc.security.rbac.core.spi;

/**
 * A {@link PermissionResolver} holding cached state that must be evicted when RBAC data changes. Decorators of a
 * caching resolver should implement this and delegate.
 */
public interface EvictablePermissionResolver extends PermissionResolver {

    void evictAll();

    void evictSubject(String subjectId);
}
