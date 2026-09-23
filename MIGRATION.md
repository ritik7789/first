# Adding RBAC to an existing Spring Boot 3 application

This guide assumes the application already authenticates users with Spring Security. The migration is incremental: existing checks keep working at every step.

## 1. Add the dependencies

```xml
<dependency>
  <groupId>com.ioc.security</groupId>
  <artifactId>rbac-spring-boot-starter</artifactId>
  <version>${rbac.version}</version>
</dependency>
<!-- PostgreSQL + Spring Boot 3.3 or later only (Boot 3.2 already includes it in flyway-core) -->
<dependency>
  <groupId>org.flywaydb</groupId>
  <artifactId>flyway-database-postgresql</artifactId>
</dependency>
<dependency>
  <groupId>com.ioc.security</groupId>
  <artifactId>rbac-test</artifactId>
  <version>${rbac.version}</version>
  <scope>test</scope>
</dependency>
```

For MySQL, add `flyway-mysql`. For SQL Server, add `flyway-sqlserver`. For Oracle, add `flyway-database-oracle`. Use the same Flyway module your application would need anyway.

## 2. Tables

At start-up the starter creates four tables: `rbac_permission`, `rbac_role`, `rbac_role_permission` and `rbac_subject_role`. It uses a **separate** Flyway history table (`rbac_schema_history`), so it never touches your application's own migrations.

- If your application uses Flyway itself, its migrations run first, then the RBAC migrations.
- If your application doesn't use Flyway, nothing changes for your schema. When no migrations exist at `spring.flyway.locations` and you haven't set `spring.flyway.enabled`, the starter turns Spring Boot's Flyway off for your application. Without this, Boot would refuse to start on an existing schema. RBAC's own migration still runs, because it uses a separate Flyway instance.
- If your DBA team owns all DDL, set `rbac.jdbc.schema.init=none` and hand them `rbac-jdbc/src/main/resources/db/rbac/migration/common/V1__rbac_schema.sql`, replacing `${prefix}` with the prefix you want.
- You can change the prefix with `rbac.jdbc.table-prefix` and the schema with `rbac.jdbc.schema.name`. If the app has several DataSources, pick one with `rbac.jdbc.data-source-bean`.

## 3. Decide how users are identified

RBAC stores a **subject id**, which is a plain string. By default it is `Authentication#getName()`. For JWT or opaque tokens you can use a claim instead:

```yaml
rbac:
  subject:
    claim: preferred_username    # or sub, user_id, email ...
```

For anything else, define a `SubjectIdResolver` bean.

## 4. Turn existing roles into RBAC data

List your current roles and the actions each one allows, then express them as permissions:

```yaml
rbac:
  super-admin-role: SUPER_ADMIN
  seed:
    roles:
      SUPER_ADMIN: { description: Break-glass }
      ADMIN:   { permissions: ["booking:*", "flight:*", rbac:read, rbac:manage] }
      MANAGER: { parent: USER, permissions: [booking:approve, report:read] }
      USER:    { permissions: [booking:read, booking:create] }
    assignments:
      - { subject: first.admin@company.com, role: SUPER_ADMIN }
```

Seeding only ever adds data, and it runs on every start-up, so it is safe to leave in place. For bulk user-to-role data, insert rows into `rbac_subject_role` with SQL. Use `'*'` in `tenant_id` for global assignments.

## 5. Keep existing checks working (optional)

If your code uses `hasRole('ADMIN')` or `hasAuthority(...)`, expose RBAC roles as authorities:

```java
@Bean
UserDetailsService userDetailsService(RbacAuthorityMapper rbac, DataSource ds) {
    return rbac.decorate(new JdbcUserDetailsManager(ds));      // form login / HTTP Basic
}

@Bean
JwtAuthenticationConverter jwtAuthenticationConverter(RbacJwtAuthoritiesConverter rbac) {
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(rbac);          // resource server
    return converter;
}
```

## 6. Switch checks to permissions, one endpoint at a time

| Before | After |
|---|---|
| `@PreAuthorize("hasRole('MANAGER')")` | `@RequiresPermission("booking:approve")` |
| `if (user.isAdmin()) ...` | `if (rbacService.hasPermission("booking:override")) ...` |
| `.requestMatchers("/admin/**").hasRole("ADMIN")` | `rbac.url-rules` + `http.authorizeHttpRequests(rbacUrlRules)` |

It's better to put checks on **service** methods than on controllers, so that message listeners and batch jobs are protected too.

## 7. Multi-tenancy (for example, airlines)

```yaml
rbac:
  multi-tenancy:
    enabled: true
    header: X-Airline      # or claim: airline
```

Assign global roles without a tenant, and airline-specific roles with `tenantId`. Reading the tenant from a header is safe: a user only receives the roles assigned to them in that tenant.

## 8. Manage at runtime

Set `rbac.admin-api.enabled=true` and give administrators `rbac:read` and `rbac:manage`. A tenant supervisor who holds `rbac:manage` in their own tenant can assign roles only in that tenant, and only roles whose permissions they already hold.

## 9. Tests

```java
@Test
@WithRbacUser(roles = "MANAGER")
void managerCanApprove() throws Exception { ... }
```

## Checklist

- [ ] Starter (and Flyway database module) added
- [ ] RBAC tables created; `rbac_schema_history` exists
- [ ] Subject id matches what you store in `rbac_subject_role.subject_id`
- [ ] Roles and permissions seeded; first super admin assigned
- [ ] Legacy checks still pass (authority bridge) or have been migrated
- [ ] `rbac.enabled` is **not** set to `false` in production. Turning it off disables enforcement.
- [ ] Audit logger `rbac.audit` shipped to your log platform
