-- RBAC schema for Microsoft SQL Server (TIMESTAMP is a row version type there, so DATETIME2 is used).
-- ${prefix} is replaced with rbac.jdbc.table-prefix (default "rbac_").
-- Global (non tenant scoped) assignments store '*' in tenant_id so the primary key works on every database.

CREATE TABLE ${prefix}permission (
    code        VARCHAR(150) NOT NULL,
    description VARCHAR(500),
    created_at  DATETIME2    NOT NULL,
    CONSTRAINT pk_${prefix}permission PRIMARY KEY (code)
);

CREATE TABLE ${prefix}role (
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(500),
    parent_name VARCHAR(100),
    created_at  DATETIME2    NOT NULL,
    CONSTRAINT pk_${prefix}role PRIMARY KEY (name),
    CONSTRAINT fk_${prefix}role_parent FOREIGN KEY (parent_name) REFERENCES ${prefix}role (name)
);

CREATE TABLE ${prefix}role_permission (
    role_name       VARCHAR(100) NOT NULL,
    permission_code VARCHAR(150) NOT NULL,
    CONSTRAINT pk_${prefix}role_permission PRIMARY KEY (role_name, permission_code),
    CONSTRAINT fk_${prefix}rp_role FOREIGN KEY (role_name) REFERENCES ${prefix}role (name) ON DELETE CASCADE,
    CONSTRAINT fk_${prefix}rp_permission FOREIGN KEY (permission_code) REFERENCES ${prefix}permission (code) ON DELETE CASCADE
);

CREATE TABLE ${prefix}subject_role (
    subject_id VARCHAR(255) NOT NULL,
    role_name  VARCHAR(100) NOT NULL,
    tenant_id  VARCHAR(100) NOT NULL,
    expires_at DATETIME2,
    granted_by VARCHAR(255),
    granted_at DATETIME2    NOT NULL,
    CONSTRAINT pk_${prefix}subject_role PRIMARY KEY (subject_id, role_name, tenant_id),
    CONSTRAINT fk_${prefix}sr_role FOREIGN KEY (role_name) REFERENCES ${prefix}role (name) ON DELETE CASCADE
);

CREATE INDEX ix_${prefix}subject_role_role ON ${prefix}subject_role (role_name);
