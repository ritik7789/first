package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.spring.event.MicrometerDecisionListener;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Micrometer counters for access decisions, active when a {@link MeterRegistry} is available (e.g. with Actuator).
 */
@AutoConfiguration(before = RbacAutoConfiguration.class,
        afterName = "org.springframework.boot.actuate.autoconfigure.metrics.CompositeMeterRegistryAutoConfiguration")
@ConditionalOnProperty(prefix = "rbac", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass(MeterRegistry.class)
public class RbacMetricsAutoConfiguration {

    @Bean
    @ConditionalOnBean(MeterRegistry.class)
    public MicrometerDecisionListener rbacMicrometerDecisionListener(MeterRegistry registry) {
        return new MicrometerDecisionListener(registry);
    }
}
