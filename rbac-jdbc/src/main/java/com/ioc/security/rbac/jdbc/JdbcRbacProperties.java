package com.ioc.security.rbac.jdbc;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code rbac.jdbc.*} properties of the JDBC store.
 */
@ConfigurationProperties(prefix = "rbac.jdbc")
public class JdbcRbacProperties {

    public enum SchemaInit {
        /** Create / upgrade the RBAC tables with Flyway (separate history table, independent of the host's Flyway). */
        FLYWAY,
        /** Do nothing; the tables are managed by the application (e.g. by copying the scripts into its own migrations). */
        NONE
    }

    /**
     * Use a JDBC store when a DataSource is available.
     */
    private boolean enabled = true;

    /**
     * Prefix for all RBAC tables. Letters, digits and underscore only.
     */
    private String tablePrefix = "rbac_";

    /**
     * Name of the DataSource bean to use when the application has several; the primary DataSource otherwise.
     */
    private String dataSourceBean;

    private final Schema schema = new Schema();

    public static class Schema {

        /**
         * How the RBAC tables are created.
         */
        private SchemaInit init = SchemaInit.FLYWAY;

        /**
         * Flyway history table for the RBAC migrations. Defaults to "{table-prefix}schema_history".
         */
        private String historyTable;

        /**
         * Flyway locations. Defaults to classpath:db/rbac/migration/{vendor}, falling back to .../common.
         */
        private String locations;

        /**
         * Database schema holding the RBAC tables; the connection's default schema when empty.
         */
        private String name;

        public SchemaInit getInit() {
            return init;
        }

        public void setInit(SchemaInit init) {
            this.init = init;
        }

        public String getHistoryTable() {
            return historyTable;
        }

        public void setHistoryTable(String historyTable) {
            this.historyTable = historyTable;
        }

        public String getLocations() {
            return locations;
        }

        public void setLocations(String locations) {
            this.locations = locations;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getTablePrefix() {
        return tablePrefix;
    }

    public void setTablePrefix(String tablePrefix) {
        this.tablePrefix = tablePrefix;
    }

    public String getDataSourceBean() {
        return dataSourceBean;
    }

    public void setDataSourceBean(String dataSourceBean) {
        this.dataSourceBean = dataSourceBean;
    }

    public Schema getSchema() {
        return schema;
    }
}
