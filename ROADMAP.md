# Generic RBAC for Spring Boot — Roadmap

> Status: **v1 implemented.** All phases are delivered; see [§10 Delivery status](#10-delivery-status--decisions).
> Target stack: **Java 17**, **Spring Boot 3.x** (tested on 3.2, 3.3, 3.4 and 3.5), Spring Security 6.x, Maven.
> Group ID / base package: `com.ioc.security` / `com.ioc.security.rbac`.

---

## 1. Goal

Build a reusable **Role-Based Access Control (RBAC) library** that any existing Spring Boot 3 application can adopt by:

1. Adding one dependency (`rbac-spring-boot-starter`).
2. Setting a few `rbac.*` properties.
3. Annotating endpoints/methods (or declaring URL rules in config).

It should **not** take over the host application's authentication (login, JWT, OAuth2, sessions, LDAP…). It only answers the question:

> *"Is the currently authenticated subject allowed to perform **action X** on **resource Y**?"*

### Design principles

| Principle | What it means in practice |
|---|---|
| **Authorization only** | Works with whatever produces a Spring Security `Authentication` in the host app. |
| **Drop-in via auto-configuration** | Spring Boot starter + `@AutoConfiguration`; every bean is `@ConditionalOnMissingBean` so the host can override anything. |
| **Pluggable storage (SPI)** | Core depends on interfaces only. Default JPA implementation provided; host can plug in its own tables, an external service, or static YAML. |
| **Non-invasive to the user model** | RBAC never owns the host's `User` entity; it references a subject by a string ID (username, UUID, email, `sub` claim…). |
| **Permission-first checks** | Code checks *permissions* (`order:approve`), not roles. Roles are just bundles of permissions → roles can change without code changes. |
| **Opt-in features** | Admin REST API, caching, auditing, multi-tenancy, schema migrations are each switchable. |
| **No surprises** | Disabled by `rbac.enabled=false`; secure-by-default (deny when no rule matches is configurable). |

---

## 2. Domain model

```
 Subject (host user id, external)                           
     │ N                                                    
     │  user_role_assignment (subject_id, role_id, [tenant_id], [expires_at])
     ▼ M                                                    
   Role ──(parent_role_id)──► Role        (role hierarchy / inheritance)
     │ N                                                    
     │  role_permission                                     
     ▼ M                                                    
 Permission = resource + ":" + action   e.g. "order:read", "order:*", "*:*"
```

| Entity | Key fields | Notes |
|---|---|---|
| `Permission` | `id`, `code` (`resource:action`), `description` | Wildcards supported: `order:*`, `*:read`, `*:*`. |
| `Role` | `id`, `name` (`ADMIN`, `MANAGER`…), `description`, `parent` | Single-inheritance hierarchy (child gets parent's permissions). Cycles rejected. |
| `RolePermission` | `role_id`, `permission_id` | Many-to-many. |
| `SubjectRole` | `subject_id` (String), `role_id`, `tenant_id` (nullable), `expires_at` (nullable) | Supports optional tenant scoping and time-bound grants. |

All tables use a configurable prefix (default `rbac_`) to avoid collisions with the host schema.

---

## 3. Module layout (Maven multi-module)

```
rbac-parent
├── rbac-core                          # Pure Java: model, SPI interfaces, permission matcher, evaluator. No Spring Web/JPA.
├── rbac-spring-boot-autoconfigure     # @AutoConfiguration, properties, Spring Security integration, AOP.
├── rbac-jpa                           # Default JPA/Hibernate store + Flyway/Liquibase scripts.
├── rbac-admin-api                     # Optional REST endpoints to manage roles/permissions/assignments.
├── rbac-spring-boot-starter           # Dependency aggregator (autoconfigure + core [+ jpa]).
├── rbac-test                          # Test helpers: @WithRbacPermissions, in-memory store.
└── rbac-sample-app                    # Demo app showing integration with JWT + JPA.
```

Host application only needs:

```xml
<dependency>
  <groupId>com.example.rbac</groupId>
  <artifactId>rbac-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>
```

---

## 4. Key extension points (SPI)

| Interface | Default impl | Purpose / why a host would replace it |
|---|---|---|
| `SubjectIdResolver` | Uses `Authentication.getName()` | Pull ID from a JWT claim (`sub`, `user_id`), a custom principal, etc. |
| `TenantResolver` | No-op (single tenant) | Resolve tenant from header, JWT claim, subdomain. |
| `RbacStore` (`RoleStore`, `PermissionStore`, `AssignmentStore`) | JPA (`rbac-jpa`) / in-memory / YAML | Host already has role tables, or roles come from an IdP/external service. |
| `PermissionResolver` | Expands roles → hierarchy → permissions | Custom inheritance rules. |
| `PermissionMatcher` | Wildcard `resource:action` matcher | Different permission syntax (e.g., `resource.action`, ant patterns). |
| `AccessDecisionListener` | Publishes Spring `ApplicationEvent`s | Audit logging, metrics, SIEM forwarding. |
| `RbacCacheManager` | Spring Cache (Caffeine if present) | Redis/Hazelcast for clustered deployments. |

All provided defaults are registered with `@ConditionalOnMissingBean`.

---

## 5. Enforcement styles offered

Host apps can use any combination:

1. **Custom annotation (AOP)**
   ```java
   @RequiresPermission("order:approve")
   @RequiresPermission(value = {"order:read", "report:read"}, logical = Logical.ANY)
   @RequiresRole("ADMIN")
   ```
   Works on controllers **and** service methods; class-level + method-level.

2. **Spring Security SpEL** (for teams already using `@PreAuthorize`)
   ```java
   @PreAuthorize("@rbac.hasPermission('order:approve')")
   @PreAuthorize("hasPermission(#orderId, 'order', 'approve')")   // via custom PermissionEvaluator
   ```

3. **URL rules in configuration** (no code change — useful for legacy apps)
   ```yaml
   rbac:
     url-rules:
       - pattern: /api/admin/**
         permissions: [admin:access]
       - pattern: /api/orders/**
         methods: [POST, PUT]
         permissions: [order:write]
   ```

4. **Programmatic API**
   ```java
   rbacService.check("order:approve");            // throws AccessDeniedException
   rbacService.hasPermission("order:approve");    // boolean
   ```

5. **GrantedAuthority bridge (optional)** — injects resolved roles (`ROLE_ADMIN`) and permissions as authorities, so existing `hasRole()/hasAuthority()` checks keep working.

Denials are raised as standard `AccessDeniedException`, so the host's existing Spring Security error handling (403) applies. An optional `ProblemDetail` (RFC 7807) handler is provided.

---

## 6. Configuration properties (draft)

```yaml
rbac:
  enabled: true
  default-decision: DENY            # DENY | ABSTAIN when no rule matches URL rules
  subject-id-claim: sub             # when using JWT; else Authentication.getName()
  super-admin-role: SUPER_ADMIN     # bypasses all checks (optional)
  authority-bridge:
    enabled: false
    role-prefix: ROLE_
  store:
    type: jpa                       # jpa | in-memory | yaml | custom
    table-prefix: rbac_
    schema-init: flyway             # flyway | liquibase | none
  cache:
    enabled: true
    ttl: 5m
  multi-tenancy:
    enabled: false
    header: X-Tenant-Id
  admin-api:
    enabled: false
    base-path: /rbac
    required-permission: rbac:manage
  audit:
    enabled: true
    log-granted: false
  seed:                              # optional bootstrap data
    roles:
      ADMIN:   { permissions: ["*:*"] }
      MANAGER: { parent: USER, permissions: ["order:approve"] }
      USER:    { permissions: ["order:read", "order:create"] }
```

Configuration metadata (`spring-configuration-metadata.json`) will be generated so IDEs auto-complete.

---

## 7. Phased delivery plan

### Phase 0 — Project scaffolding
- Maven multi-module parent, Java 17 toolchain, Spring Boot 3.x BOM.
- Code style (Spotless), Checkstyle, JaCoCo, GitHub Actions CI (build + test).
- **Deliverable:** empty modules compile, CI green.

### Phase 1 — Core (`rbac-core`)
- Domain model (records / immutable types).
- SPI interfaces from §4.
- `PermissionMatcher` with wildcard support.
- `PermissionResolver` with role hierarchy + cycle detection.
- `RbacEvaluator` (decision engine: subject → roles → permissions → decision).
- In-memory store.
- **Deliverable:** pure unit-tested library, no Spring dependency.

### Phase 2 — Spring Boot auto-configuration
- `RbacProperties` (`@ConfigurationProperties("rbac")`).
- `RbacAutoConfiguration` registered via `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.
- `SubjectIdResolver` from `SecurityContextHolder`.
- `@RequiresPermission` / `@RequiresRole` + AOP aspect.
- `@rbac` SpEL bean + `PermissionEvaluator` for `@PreAuthorize`.
- URL-rule `AuthorizationManager` plugged into the host's `SecurityFilterChain` via a customizer (host opts in with one line).
- Optional `GrantedAuthority` bridge.
- **Deliverable:** works with in-memory/YAML store in a test app.

### Phase 3 — Persistence (`rbac-jpa`)
- JPA entities with configurable table prefix (`PhysicalNamingStrategy` scoped to RBAC entities).
- Repositories + `RbacStore` implementation.
- Flyway **and** Liquibase scripts (H2, PostgreSQL, MySQL, Oracle, SQL Server compatible).
- Seed data loader from properties.
- Caching of resolved permissions per subject (+ eviction on change).
- **Deliverable:** Testcontainers integration tests on PostgreSQL & MySQL.

### Phase 4 — Admin REST API (`rbac-admin-api`, optional)
- CRUD for roles, permissions, role-permission mapping, subject assignments.
- `GET /rbac/me/permissions` — effective permissions of current user (useful for frontends to show/hide UI).
- Protected by `rbac:manage` permission; validation; paging; `ProblemDetail` errors.
- OpenAPI annotations (springdoc, optional dependency).
- **Deliverable:** documented, tested endpoints.

### Phase 5 — Cross-cutting features
- Audit events (`AccessGrantedEvent`, `AccessDeniedEvent`, `RoleAssignedEvent`…).
- Micrometer metrics (decisions count, cache hit rate).
- Multi-tenancy (tenant-scoped assignments).
- Time-bound role assignments (`expires_at`).
- Cache invalidation hooks for clustered setups.

### Phase 6 — Testing support (`rbac-test`)
- `@WithRbacPermissions({"order:read"})` / `@WithRbacRoles("ADMIN")` for `@WebMvcTest` / `@SpringBootTest`.
- In-memory store auto-wired in tests.

### Phase 7 — Sample app & migration guide
- `rbac-sample-app`: orders API secured with JWT (resource server) + RBAC.
- `MIGRATION.md`: step-by-step for adopting in an existing app:
  1. Add dependency.
  2. Decide store: new `rbac_*` tables vs. adapter to existing role tables (`RbacStore` impl).
  3. Configure `SubjectIdResolver` to match your principal.
  4. Map existing roles → permissions (seed YAML or SQL script).
  5. Enable authority bridge so current `hasRole()` checks keep working.
  6. Gradually replace role checks with `@RequiresPermission`.
- `README.md` with quickstart and full property reference.

### Phase 8 — Release hardening
- Compatibility test matrix: Spring Boot 3.2 / 3.3 / 3.4 / 3.5, Java 17 & 21.
- Security review (default-deny, super-admin bypass, cache poisoning, admin API privilege escalation — e.g. a user cannot grant a permission they don't hold).
- Publishing setup (Maven Central / GitHub Packages), semantic versioning.

---

## 8. Out of scope (for v1)

- Authentication (login, password storage, token issuing) — host app's responsibility.
- ABAC / policy languages (OPA, XACML) — the `PermissionResolver` SPI leaves room for this later.
- Row/object-level ownership rules ("user can edit **own** orders") — possible via custom `PermissionEvaluator`, documented as an extension example only.
- Admin UI (only REST API).
- Reactive (WebFlux) support — can be added as a v2 module (`rbac-reactive`).

---

## 9. Open questions for you

1. **Group ID / base package** — e.g. `com.<yourcompany>.rbac`? (Placeholder: `com.example.rbac`.)
2. **Build tool** — Maven (planned) or Gradle?
3. **Scope of v1** — implement all phases, or stop after Phase 3/4 for a first review?
4. **Databases** to officially support — PostgreSQL + MySQL + H2 enough, or also Oracle/SQL Server?
5. **Migration tool** — Flyway, Liquibase, or both?
6. **Multi-tenancy** — needed in v1?
7. **WebFlux** — do any target apps use reactive stack?
8. **Existing role tables** — do your target apps already have `roles`/`user_roles` tables you'd want an adapter for rather than new `rbac_*` tables?

**Answers (review of 2026-09-23):**
1. `com.ioc.security`
2. Maven
3. All phases
4. PostgreSQL first, but keep the schema portable to any relational database
5. Flyway
6. Multi-tenancy included in v1
7. No WebFlux yet (airline applications are in progress), so the core stays reactive-ready
8. Create new tables

---

## 10. Delivery status & decisions

| Phase | Status | Notes |
|---|---|---|
| 0: Scaffolding | Done | Maven multi-module, Java 17 `release`, JaCoCo, GitHub Actions matrix (Java 17/21 × Boot 3.2–3.5). |
| 1: Core | Done | Model, SPI, wildcard matcher, hierarchical resolver, TTL cache, `RbacAdministration` (validation, cycle detection, change listeners), in-memory store. |
| 2: Auto-configuration | Done | Annotations through a Spring AOP advisor (no AspectJ, no `@EnableMethodSecurity` needed), `@rbac` SpEL bean, `PermissionEvaluator` with an expression handler, URL rules, subject and tenant resolvers, authority bridge. |
| 3: Persistence | Done, **JDBC instead of JPA** | See decision D1. Flyway with a separate history table; common SQL plus a SQL Server variant. |
| 4: Admin API | Done | CRUD, `/me`, effective permissions, ProblemDetail errors, tenant-scoped management, protection against privilege escalation. springdoc annotations not added (optional dependency; can be added later). |
| 5: Cross-cutting | Done | Audit events and `rbac.audit` logger, Micrometer counters, multi-tenancy, expiring assignments, cache eviction and `RbacDataChangedEvent` for clusters. |
| 6: Testing support | Done | `@WithRbacUser`, `@AutoConfigureRbac`, auto-included in `@WebMvcTest`. |
| 7: Sample and migration guide | Done | Airline sample (tenants = airlines, header `X-Airline`), `README.md`, `MIGRATION.md`. The sample uses HTTP Basic rather than JWT, to keep it self-contained; the JWT integration ships as `RbacJwtAuthoritiesConverter` and `rbac.subject.claim`. |
| 8: Hardening | Done (partly) | Compatibility checked locally on Boot 3.2.12, 3.3.13, 3.4.10 and 3.5.16. Security review fixes: super-admin escalation (D4) and a guard for the host's Flyway (D3). Publishing: a `release` profile attaches sources and javadoc. `distributionManagement` (Nexus, Artifactory or GitHub Packages) still needs your repository URL. |

**Decisions made during implementation**

- **D1: JDBC store instead of JPA.** A library's JPA entities are only picked up if the host changes its `@EntityScan`, which then overrides Boot's defaults. They can also clash with the host's naming strategy. Plain SQL through `JdbcTemplate` works the same in JPA, JDBC and MyBatis applications. It joins a host transaction on the same DataSource when one is active.
- **D2: Portable schema.** Natural keys (role name, permission code) and no identity or sequence columns. Global assignments store `'*'` as `tenant_id`, so the composite primary key works on every database, since NULL handling in unique keys differs between vendors. Timestamps are stored as UTC `TIMESTAMP` (`DATETIME2` on SQL Server).
- **D3: Flyway isolation.** RBAC uses its own Flyway instance and its own `rbac_schema_history` table. It runs after the host's Flyway, so a host `V1` is never skipped by a baseline. If the host has no Flyway migrations of its own, Boot's host Flyway is turned off by default, because otherwise it would refuse to start on an existing schema.
- **D4: Super-admin escalation.** The super-admin role grants no explicit permissions, so a "can only grant what you hold" check alone would let any RBAC admin assign it. It and any role inheriting from it can only be granted by super admins.
- **D5: `flyway-database-postgresql` is not in the starter.** Boot 3.2 manages Flyway 9, where PostgreSQL support is part of `flyway-core`. Forcing the separate module would mix Flyway versions, so hosts on Boot 3.3+ add that one dependency themselves.
- **D6: Role checks are weaker than permission checks.** A role that grants no permissions passes the anti-escalation check, so `@RequiresRole` on such a role can be satisfied by any RBAC admin. Prefer `@RequiresPermission`.

**Next candidates (v1.x / v2)**
- `rbac-reactive` module for WebFlux (the core has no servlet dependency, so only the Spring adapter is needed).
- Redis- or Kafka-based cache invalidation adapter.
- springdoc/OpenAPI annotations for the admin API.
- Ownership / ABAC hooks (for example, "agent may only cancel bookings of their own office").
