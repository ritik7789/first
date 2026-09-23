package com.ioc.security.rbac.jdbc;

import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

class H2PostgresModeJdbcRbacStoreTest extends AbstractJdbcRbacStoreTest {

    private static final DataSource DATA_SOURCE = new DriverManagerDataSource(
            "jdbc:h2:mem:rbac-pg;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1",
            "sa", "");

    @Override
    protected DataSource dataSource() {
        return DATA_SOURCE;
    }
}
