package com.ioc.security.rbac.jdbc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;

import java.io.IOException;
import java.util.Map;

/**
 * The RBAC starter brings Flyway onto the classpath for its own tables. That also activates Spring Boot's Flyway
 * auto-configuration for the host application, which fails on an existing schema when the host never used Flyway
 * ("non-empty schema but no schema history table").
 *
 * <p>When the host has not configured {@code spring.flyway.enabled} and has no migrations at its Flyway locations,
 * this post-processor defaults {@code spring.flyway.enabled=false}. The RBAC schema is unaffected: it is migrated by
 * a separate Flyway instance. Applications that do use Flyway are never touched.
 */
public class RbacFlywayEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    static final String SOURCE_NAME = "rbacHostFlywayDefaults";
    private static final String DEFAULT_LOCATION = "classpath:db/migration";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (environment.containsProperty("spring.flyway.enabled")
                || !environment.getProperty("rbac.enabled", Boolean.class, true)
                || !environment.getProperty("rbac.jdbc.enabled", Boolean.class, true)
                || !isClassPresent("org.flywaydb.core.Flyway", application)) {
            return;
        }
        String[] locations = environment.getProperty("spring.flyway.locations", String[].class,
                new String[]{DEFAULT_LOCATION});
        ClassLoader classLoader = application != null ? application.getClassLoader() : getClass().getClassLoader();
        if (!hasMigrations(locations, new PathMatchingResourcePatternResolver(classLoader))) {
            environment.getPropertySources().addLast(new MapPropertySource(SOURCE_NAME,
                    Map.of("spring.flyway.enabled", "false")));
        }
    }

    static boolean hasMigrations(String[] locations, ResourcePatternResolver resolver) {
        for (String raw : locations) {
            String location = raw.trim();
            if (!location.startsWith("classpath:")) {
                return true; // filesystem / custom locations: assume the application knows what it does
            }
            String path = location.substring("classpath:".length()).replace("{vendor}", "*");
            path = path.startsWith("/") ? path.substring(1) : path;
            try {
                for (Resource resource : resolver.getResources("classpath*:" + path + "/**/*")) {
                    String name = resource.getFilename();
                    if (name != null && resource.isReadable()
                            && (name.endsWith(".sql") || name.endsWith(".class"))) {
                        return true;
                    }
                }
            } catch (IOException ex) {
                return true;
            }
        }
        return false;
    }

    private static boolean isClassPresent(String name, SpringApplication application) {
        try {
            ClassLoader cl = application != null ? application.getClassLoader()
                    : RbacFlywayEnvironmentPostProcessor.class.getClassLoader();
            Class.forName(name, false, cl);
            return true;
        } catch (ClassNotFoundException | LinkageError ex) {
            return false;
        }
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
