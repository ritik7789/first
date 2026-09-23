package com.ioc.security.rbac.jdbc;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;

/**
 * Runs the store contract against a real PostgreSQL. Skipped automatically when Docker is not available.
 */
@Testcontainers(disabledWithoutDocker = true)
class PostgresJdbcRbacStoreTest extends AbstractJdbcRbacStoreTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static DataSource dataSource;

    @BeforeAll
    static void connect() {
        dataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    @Override
    protected DataSource dataSource() {
        return dataSource;
    }
}
