package com.ioc.security.sample.airline;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo airline API secured with the RBAC starter. Airlines are tenants (header {@code X-Airline}).
 */
@SpringBootApplication
public class AirlineApplication {

    public static void main(String[] args) {
        SpringApplication.run(AirlineApplication.class, args);
    }
}
