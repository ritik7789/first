package com.ioc.security.rbac.jdbc;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.jdbc.DatabaseDriver;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.jdbc.support.MetaDataAccessException;

import javax.sql.DataSource;
import java.sql.DatabaseMetaData;
import java.util.Map;

/**
 * Creates / upgrades the RBAC tables with a dedicated Flyway instance and history table, so it never interferes with
 * the host application's own Flyway migrations (which may or may not exist).
 */
public class RbacSchemaMigrator implements InitializingBean {

    static final String BASE_LOCATION = "db/rbac/migration/";
    private static final Logger log = LoggerFactory.getLogger(RbacSchemaMigrator.class);

    private final DataSource dataSource;
    private final JdbcRbacProperties properties;

    public RbacSchemaMigrator(DataSource dataSource, JdbcRbacProperties properties) {
        this.dataSource = dataSource;
        this.properties = properties;
    }

    @Override
    public void afterPropertiesSet() {
        JdbcRbacProperties.Schema schema = properties.getSchema();
        String prefix = properties.getTablePrefix();
        String historyTable = schema.getHistoryTable() != null ? schema.getHistoryTable() : prefix + "schema_history";
        String locations = schema.getLocations() != null ? schema.getLocations() : "classpath:" + vendorLocation();

        var configuration = Flyway.configure(getClass().getClassLoader())
                .dataSource(dataSource)
                .table(historyTable)
                .locations(locations.split(","))
                .placeholders(Map.of("prefix", prefix))
                .baselineOnMigrate(true)
                .baselineVersion("0");
        if (schema.getName() != null && !schema.getName().isBlank()) {
            configuration.schemas(schema.getName()).placeholders(Map.of("prefix", schema.getName() + "." + prefix));
        }
        MigrateResult result = configuration.load().migrate();
        log.info("RBAC schema up to date ({} migration(s) applied, locations={}, history table={})",
                result.migrationsExecuted, locations, historyTable);
    }

    private String vendorLocation() {
        String vendor = vendor();
        if (vendor != null && new ClassPathResource(BASE_LOCATION + vendor + "/V1__rbac_schema.sql").exists()) {
            return BASE_LOCATION + vendor;
        }
        return BASE_LOCATION + "common";
    }

    private String vendor() {
        try {
            String url = JdbcUtils.extractDatabaseMetaData(dataSource, DatabaseMetaData::getURL);
            DatabaseDriver driver = DatabaseDriver.fromJdbcUrl(url);
            return driver == DatabaseDriver.UNKNOWN ? null : driver.getId();
        } catch (MetaDataAccessException ex) {
            return null;
        }
    }
}
