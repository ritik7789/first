package com.ioc.security.sample.airline;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Shows the other enforcement styles an existing application may already use.
 */
@RestController
@RequestMapping("/api/reports")
public class ReportController {

    /** Protected only by the URL rule in application.yml (no annotation). */
    @GetMapping("/revenue")
    public Map<String, Object> revenue() {
        return Map.of("revenue", 1_250_000);
    }

    /** SpEL with the "rbac" bean. */
    @GetMapping("/load-factor")
    @PreAuthorize("@rbac.hasPermission('report:read')")
    public Map<String, Object> loadFactor() {
        return Map.of("loadFactor", 0.87);
    }

    /** Legacy role check, still working thanks to the authority bridge in SecurityConfig. */
    @GetMapping("/legacy")
    @PreAuthorize("hasRole('OPS_MANAGER')")
    public Map<String, Object> legacy() {
        return Map.of("legacy", true);
    }
}
