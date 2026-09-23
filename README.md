# IOC RBAC: role-based access control for Spring Boot 3

A reusable RBAC library for **Java 17+** and **Spring Boot 3.2 – 3.5**. Add one dependency, set a few properties, and protect endpoints and services with permissions.

- **Authorization only.** The library works with whatever authentication your app already uses (JWT, OAuth2 login, HTTP Basic, LDAP, sessions and so on).
- **Model:** users (called *subjects* here) are assigned *roles*. Roles bundle *permissions* such as `booking:cancel`, and a role can inherit from a parent role.
- **Multi-tenant:** a role can be assigned globally or only within one tenant (for example, one airline).
- **Portable storage:** plain JDBC with Flyway-managed tables. The tables work on PostgreSQL, MySQL/MariaDB, H2, Oracle and SQL Server. An in-memory store is available as a fallback, and you can plug in your own store.
- Optional **admin REST API** with protection against privilege escalation. Also includes audit events, Micrometer metrics and test helpers.

See [`ROADMAP.md`](ROADMAP.md) for the design and [`MIGRATION.md`](MIGRATION.md) for adding it to an existing application.

---

## Modules

| Artifact | Purpose |
|---|---|
| `rbac-core` | Plain Java: model, SPI, wildcard matcher, permission resolver, administration logic. No Spring. |
| `rbac-spring-boot-autoconfigure` | Spring Boot / Spring Security integration: annotations, SpEL, URL rules, subject/tenant resolution, caching, events, metrics, seeding. |
| `rbac-jdbc` | `JdbcRbacStore` plus Flyway migrations (`db/rbac/migration/{common,sqlserver}`). |
| `rbac-admin-api` | Optional REST API (`rbac.admin-api.enabled=true`). |
| `rbac-spring-boot-starter` | **The dependency most applications need.** It bundles all of the above, plus Spring Security and Flyway. |
| `rbac-test` | `@WithRbacUser`, `@AutoConfigureRbac`. Use with `test` scope. |
| `rbac-sample-app` | Demo airline API that exercises every feature. |

## Quick start

```xml
<dependency>
  <groupId>com.ioc.security</groupId>
  <artifactId>rbac-spring-boot-starter</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
<!-- PostgreSQL with Spring Boot 3.3+ (Flyway 10+) also needs: -->
<dependency>
  <groupId>org.flywaydb</groupId>
  <artifactId>flyway-database-postgresql</artifactId>
</dependency>
<dependency>
  <groupId>com.ioc.security</groupId>
  <artifactId>rbac-test</artifactId>
  <version>1.0.0-SNAPSHOT</version>
  <scope>test</scope>
</dependency>
```

```yaml
rbac:
  super-admin-role: SUPER_ADMIN
  seed:                              # optional, additive and idempotent at start-up
    roles:
      PASSENGER:     { permissions: [flight:read, booking:read] }
      BOOKING_AGENT: { parent: PASSENGER, permissions: [booking:create, booking:cancel] }
      SUPER_ADMIN:   { description: Everything }
    assignments:
      - { subject: admin@example.com, role: SUPER_ADMIN }
```

```java
@RestController
class BookingController {

    @PostMapping("/bookings/{id}/cancel")
    @RequiresPermission("booking:cancel")
    Booking cancel(@PathVariable long id) { ... }
}
```

When a DataSource exists, the RBAC tables (`rbac_permission`, `rbac_role`, `rbac_role_permission`, `rbac_subject_role`) are created automatically. The RBAC migration uses its own Flyway history table, `rbac_schema_history`.

Run the demo:

```bash
mvn install
java -jar rbac-sample-app/target/rbac-sample-app-1.0.0-SNAPSHOT.jar
curl -u agent-sky:password -H 'X-Airline: SKY' localhost:8080/api/rbac/me
```

Demo users: `root`, `ops`, `rbac-admin`, `agent-sky`, `agent-blue`, `supervisor-sky` and `passenger`. They all use the password `password`. To run it on PostgreSQL instead of H2, use `docker compose -f rbac-sample-app/docker-compose.yml up -d` and the `postgres` Spring profile.

---

## Concepts

| Concept | Rules |
|---|---|
| **Permission** | One or more `:`-separated segments, such as `booking:read` or `flight:schedule:update`. Each segment uses `[a-z0-9_.-]`, and codes are stored in lower case. |
| **Wildcards** | A `*` in the middle matches exactly one segment: `*:read` matches `flight:read`. A `*` at the end matches everything after it: `booking:*` matches `booking:seat:assign`. A lone `*` matches every permission. |
| **Role** | A name (`[A-Za-z0-9_.-]`, case sensitive) with its own permissions and at most one parent. The role inherits all of the parent's permissions. The library rejects hierarchy cycles. |
| **Assignment** | Links a subject, a role and an optional tenant, with an optional `expiresAt`. A global assignment (no tenant) applies in every tenant. A tenant assignment applies only in that tenant. |
| **Subject id** | `Authentication#getName()`, or a token claim set with `rbac.subject.claim`. The library never touches your user table. |
| **Super admin** | Optional (`rbac.super-admin-role`). Holders pass every check. Only another super admin can grant this role through the admin API. |

## Ways to enforce access

```java
@RequiresPermission("booking:cancel")                                              // AOP, on classes and methods
@RequiresPermission(value = {"booking:cancel", "booking:force-cancel"}, logical = Logical.ANY)
@RequiresRole("OPS_MANAGER")                                                       // prefer permissions

@PreAuthorize("@rbac.hasPermission('report:read')")                                // SpEL bean "rbac"
@PreAuthorize("hasPermission(#id, 'booking', 'cancel')")                           // PermissionEvaluator

rbacService.checkPermission("booking:cancel");                                     // programmatic (throws)
if (rbacService.hasAnyPermission("report:read", "report:*")) { ... }                // programmatic (boolean)
```

- `@RequiresPermission` and `@RequiresRole` work on controllers and on any Spring bean, with no need for `@EnableMethodSecurity`. When both the class and the method are annotated, both requirements must be met.
- If the caller isn't authenticated, the check throws `AuthenticationCredentialsNotFoundException` (401). If the caller lacks the permission, it throws `AccessDeniedException` (403). Your existing Spring Security error handling applies to both.
- `@PreAuthorize` requires `@EnableMethodSecurity`. The starter registers a `MethodSecurityExpressionHandler` that `hasPermission(...)` uses, unless you define your own.

**URL rules.** These need no code change, which helps with legacy endpoints:

```yaml
rbac:
  url-rules:
    - { pattern: /api/reports/revenue, methods: [GET], permissions: [report:revenue] }
    - { patterns: [/actuator/**], permissions: [ops:monitor] }
```

```java
http.authorizeHttpRequests(rbacUrlRules)                                  // first: RBAC rules
    .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());   // then your catch-all
```

**Keeping legacy `hasRole()` checks working.** `RbacAuthorityMapper` can expose RBAC roles as `ROLE_*` authorities and permissions as plain authorities:

```java
@Bean UserDetailsService users(RbacAuthorityMapper mapper) { return mapper.decorate(existingUserDetailsService); }

// JWT resource server
JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
converter.setJwtGrantedAuthoritiesConverter(rbacJwtAuthoritiesConverter);
```

These authorities are computed at login time. RBAC annotations and `RbacService` are always evaluated live.

## Configuration reference

| Property | Default | Description |
|---|---|---|
| `rbac.enabled` | `true` | Master switch. **When false, RBAC annotations are not enforced.** |
| `rbac.super-admin-role` | (none) | Role that bypasses all checks. |
| `rbac.subject.claim` | (none) | Token claim to use as the subject id (OAuth2 resource server). Otherwise the library uses `Authentication#getName()`. |
| `rbac.multi-tenancy.enabled` | `false` | Turns on tenant-scoped assignments. |
| `rbac.multi-tenancy.header` | `X-Tenant-Id` | Request header that carries the tenant. |
| `rbac.multi-tenancy.claim` | (none) | Token claim that carries the tenant. It takes precedence over the header. |
| `rbac.cache.enabled` / `ttl` / `max-entries` | `true` / `5m` / `10000` | Cache of resolved permissions per subject and tenant. Local changes evict it immediately. |
| `rbac.authorities.role-prefix` / `permission-prefix` | `ROLE_` / `""` | Prefixes used by `RbacAuthorityMapper`. |
| `rbac.audit.enabled` / `log-granted` | `true` / `false` | Publishes `RbacAccessEvent` (denials, plus grants if `log-granted`) and logs to the `rbac.audit` logger. |
| `rbac.method-security.enabled` / `order` | `true` / `100` | Enforcement of the annotations, and the advisor's order. |
| `rbac.url-rules[]` | (none) | `pattern(s)`, `methods`, `permissions`, `roles`, `logical` (`ALL`/`ANY`). |
| `rbac.seed.permissions` / `roles` / `assignments` | (none) | Start-up data. Seeding is additive and never deletes anything. |
| `rbac.jdbc.enabled` | `true` | Use the JDBC store when a DataSource exists. |
| `rbac.jdbc.table-prefix` | `rbac_` | Prefix for table names. |
| `rbac.jdbc.data-source-bean` | (none) | Name of the DataSource bean to use when the app has several. |
| `rbac.jdbc.schema.init` | `flyway` | `flyway` or `none` (for when you manage the DDL yourself). |
| `rbac.jdbc.schema.history-table` / `locations` / `name` | derived | Flyway history table, script location, and target schema. |
| `rbac.admin-api.enabled` | `false` | Turns on the REST API. |
| `rbac.admin-api.base-path` | `/rbac` | Base path of the API. |
| `rbac.admin-api.read-permission` / `manage-permission` | `rbac:read` / `rbac:manage` | Permissions the API requires. |

## Admin REST API

All paths are relative to `rbac.admin-api.base-path`. Errors are returned as RFC 7807 `ProblemDetail`: 400 for invalid input, 404 when something doesn't exist, 409 on conflicts.

| Method and path | Requires |
|---|---|
| `GET /me` | Being authenticated. Returns the caller's effective roles and permissions, which a front end can use to show or hide features. |
| `GET /permissions`, `GET /roles`, `GET /roles/{name}`, `GET /roles/{name}/assignments`, `GET /subjects/{id}/assignments`, `GET /subjects/{id}/permissions?tenantId=` | read permission |
| `POST /permissions`, `DELETE /permissions/{code}` | manage permission, global |
| `POST /roles`, `PUT /roles/{name}`, `DELETE /roles/{name}`, `POST /roles/{name}/permissions`, `DELETE /roles/{name}/permissions/{code}` | manage permission, global |
| `POST /subjects/{id}/assignments` `{role, tenantId?, expiresAt?}`, `DELETE /subjects/{id}/assignments/{role}?tenantId=` | manage permission **in the assignment's tenant** |

**Privilege-escalation protection.** You can only add permissions to a role, set a role's parent, or assign a role if you hold every permission involved yourself, in that scope. Only super admins can grant the super-admin role, or any role that inherits from it. As a result, a tenant supervisor can manage agents in its own airline but can't grant anything beyond its own rights.

## Extension points

Each default below is registered with `@ConditionalOnMissingBean`. To replace one, declare your own bean.

| Bean type | Default | Replace it to… |
|---|---|---|
| `RbacStore` / `RbacManagementStore` | `JdbcRbacStore`, or `InMemoryRbacStore` without a DataSource | Read roles from existing tables, an IdP or a remote service. A read-only `RbacStore` is enough; the admin API and seeding are then switched off. |
| `SubjectIdResolver` | `DefaultSubjectIdResolver` | Map a custom principal to a subject id. |
| `TenantResolver` | header or claim | Resolve the tenant from a subdomain, a path, and so on. |
| `PermissionMatcher` | `WildcardPermissionMatcher` | Use a different permission syntax. |
| `PermissionResolver` | hierarchical resolver plus cache | Custom inheritance, or a distributed cache. |
| `RbacDecisionListener` | events and Micrometer | Push decisions to a SIEM. |
| `RbacChangeListener` | (none) | React to data changes, for example to broadcast cache eviction to other nodes. |

For **clustered deployments**, each node caches permissions for `rbac.cache.ttl`. You can lower the TTL, or listen for `RbacDataChangedEvent` and broadcast it (Redis pub/sub, Kafka, …) so that every node calls `evictAll()` on its `EvictablePermissionResolver`.

## Testing your application

```java
@WebMvcTest(BookingController.class)          // RBAC is auto-configured in the slice when rbac-test is present
class BookingControllerTest {
    @Test @WithRbacUser(permissions = "booking:cancel")         void canCancel() { ... }
    @Test @WithRbacUser(value = "alice", roles = "BOOKING_AGENT") void agent()   { ... }  // real role definitions
}
```

`@WithRbacUser` doesn't write anything to the store. For other test slices, add `@AutoConfigureRbac`.

## Building

```bash
mvn verify                                               # Spring Boot 3.5 (default)
mvn verify -Dspring-boot.version=3.3.13                  # other 3.x lines
mvn verify -Dspring-boot.version=3.2.12 -Dlegacy-flyway  # Boot 3.2 ships Flyway 9 (PostgreSQL built in)
```

The PostgreSQL Testcontainers tests run automatically when Docker is available. CI (`.github/workflows/ci.yml`) covers Java 17 and 21 on Boot 3.2, 3.3, 3.4 and 3.5.
