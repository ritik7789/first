package com.ioc.security.rbac.autoconfigure;

import com.ioc.security.rbac.spring.Logical;
import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.annotation.RequiresPermission;
import com.ioc.security.rbac.spring.annotation.RequiresRole;
import com.ioc.security.rbac.spring.web.RbacUrlRules;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableMethodSecurity
public class TestApplication {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, RbacUrlRules rbacUrlRules) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(rbacUrlRules)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @RestController
    @RequestMapping("/flights")
    static class FlightController {

        private final FlightService service;
        private final RbacService rbac;

        FlightController(FlightService service, RbacService rbac) {
            this.service = service;
            this.rbac = rbac;
        }

        @GetMapping
        @RequiresPermission("flight:read")
        String list() {
            return "flights";
        }

        @PostMapping("/{id}/cancel")
        String cancel(@PathVariable String id) {
            return service.cancel(id);
        }

        @GetMapping("/any")
        @RequiresPermission(value = {"flight:delete", "flight:read"}, logical = Logical.ANY)
        String any() {
            return "any";
        }

        @GetMapping("/supervisor")
        @RequiresRole("SUPERVISOR")
        String supervisor() {
            return "supervisor";
        }

        @GetMapping("/spel")
        @PreAuthorize("@rbac.hasPermission('flight:read')")
        String spel() {
            return "spel";
        }

        @GetMapping("/evaluator/{id}")
        @PreAuthorize("hasPermission(#id, 'flight', 'read')")
        String evaluator(@PathVariable String id) {
            return "evaluator";
        }

        @GetMapping("/programmatic")
        String programmatic() {
            rbac.checkPermission("flight:read");
            return "programmatic";
        }

        @GetMapping("/url-rule")
        String urlRule() {
            return "url-rule";
        }
    }

    @Service
    @RequiresPermission("flight:read")
    static class FlightService {

        @RequiresPermission("flight:cancel")
        public String cancel(String id) {
            return "cancelled " + id;
        }

        @Override
        public String toString() {
            return "FlightService";
        }
    }
}
