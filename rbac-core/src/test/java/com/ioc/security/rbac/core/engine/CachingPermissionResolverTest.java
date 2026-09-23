package com.ioc.security.rbac.core.engine;

import com.ioc.security.rbac.core.model.EffectivePermissions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class CachingPermissionResolverTest {

    @Test
    void servesRepeatedLookupsFromCacheUntilExpiredOrEvicted() {
        AtomicInteger calls = new AtomicInteger();
        long[] time = {0};
        CachingPermissionResolver cache = new CachingPermissionResolver((s, t) -> {
            calls.incrementAndGet();
            return EffectivePermissions.none(s, t);
        }, Duration.ofSeconds(10), 100, () -> time[0]);

        cache.resolve("a", null);
        cache.resolve("a", null);
        assertThat(calls).hasValue(1);

        cache.resolve("a", "AI");
        assertThat(calls).hasValue(2);

        time[0] = Duration.ofSeconds(11).toNanos();
        cache.resolve("a", null);
        assertThat(calls).hasValue(3);

        cache.evictSubject("a");
        cache.resolve("a", null);
        assertThat(calls).hasValue(4);
    }

    @Test
    void neverGrowsBeyondMaxEntries() {
        CachingPermissionResolver cache = new CachingPermissionResolver(EffectivePermissions::none,
                Duration.ofMinutes(5), 10);
        for (int i = 0; i < 100; i++) {
            cache.resolve("user-" + i, null);
        }
        assertThat(cache.size()).isLessThanOrEqualTo(10);
    }
}
