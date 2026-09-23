package com.ioc.security.rbac.spring.event;

import com.ioc.security.rbac.spring.AccessDecision;
import com.ioc.security.rbac.spring.RbacDecisionListener;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Counts decisions in {@code rbac.access.decisions} tagged by {@code outcome} (granted/denied) and {@code type}.
 */
public class MicrometerDecisionListener implements RbacDecisionListener {

    private final Counter permissionGranted;
    private final Counter permissionDenied;
    private final Counter roleGranted;
    private final Counter roleDenied;

    public MicrometerDecisionListener(MeterRegistry registry) {
        permissionGranted = counter(registry, "granted", "permission");
        permissionDenied = counter(registry, "denied", "permission");
        roleGranted = counter(registry, "granted", "role");
        roleDenied = counter(registry, "denied", "role");
    }

    @Override
    public void onDecision(AccessDecision decision) {
        boolean permission = decision.type() == AccessDecision.Type.PERMISSION;
        if (decision.granted()) {
            (permission ? permissionGranted : roleGranted).increment();
        } else {
            (permission ? permissionDenied : roleDenied).increment();
        }
    }

    private static Counter counter(MeterRegistry registry, String outcome, String type) {
        return Counter.builder("rbac.access.decisions")
                .description("RBAC access decisions")
                .tag("outcome", outcome)
                .tag("type", type)
                .register(registry);
    }
}
