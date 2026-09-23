package com.ioc.security.rbac.core.engine;

import com.ioc.security.rbac.core.model.EffectivePermissions;
import com.ioc.security.rbac.core.spi.EvictablePermissionResolver;
import com.ioc.security.rbac.core.spi.PermissionResolver;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Decorator caching resolved permissions per (subject, tenant) for a fixed time-to-live.
 * Call {@link #evictAll()} or {@link #evictSubject(String)} after RBAC data changes.
 */
public class CachingPermissionResolver implements EvictablePermissionResolver {

    private record Key(String subjectId, String tenantId) {
    }

    private record Entry(EffectivePermissions value, long expiresAtNanos) {
    }

    private final PermissionResolver delegate;
    private final long ttlNanos;
    private final int maxEntries;
    private final LongSupplier nanoClock;
    private final Map<Key, Entry> cache = new ConcurrentHashMap<>();

    public CachingPermissionResolver(PermissionResolver delegate, Duration ttl, int maxEntries) {
        this(delegate, ttl, maxEntries, System::nanoTime);
    }

    CachingPermissionResolver(PermissionResolver delegate, Duration ttl, int maxEntries, LongSupplier nanoClock) {
        this.delegate = Objects.requireNonNull(delegate);
        this.ttlNanos = ttl.toNanos();
        this.maxEntries = maxEntries;
        this.nanoClock = nanoClock;
    }

    @Override
    public EffectivePermissions resolve(String subjectId, String tenantId) {
        Key key = new Key(subjectId, tenantId);
        long now = nanoClock.getAsLong();
        Entry entry = cache.get(key);
        if (entry != null && now - entry.expiresAtNanos() < 0) {
            return entry.value();
        }
        EffectivePermissions value = delegate.resolve(subjectId, tenantId);
        if (cache.size() >= maxEntries) {
            cache.entrySet().removeIf(e -> now - e.getValue().expiresAtNanos() >= 0);
            if (cache.size() >= maxEntries) {
                cache.clear();
            }
        }
        cache.put(key, new Entry(value, now + ttlNanos));
        return value;
    }

    @Override
    public void evictAll() {
        cache.clear();
    }

    @Override
    public void evictSubject(String subjectId) {
        cache.keySet().removeIf(k -> Objects.equals(k.subjectId(), subjectId));
    }

    public int size() {
        return cache.size();
    }
}
