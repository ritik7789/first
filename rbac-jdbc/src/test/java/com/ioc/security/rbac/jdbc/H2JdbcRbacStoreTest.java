package com.ioc.security.rbac.jdbc;

import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

class H2JdbcRbacStoreTest extends AbstractJdbcRbacStoreTest {

    private static final DataSource DATA_SOURCE =
            new DriverManagerDataSource("jdbc:h2:mem:rbac-plain;DB_CLOSE_DELAY=-1", "sa", "");

    @Override
    protected DataSource dataSource() {
        return DATA_SOURCE;
    }
}
