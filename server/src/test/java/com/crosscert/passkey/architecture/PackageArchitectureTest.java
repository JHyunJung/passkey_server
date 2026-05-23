package com.crosscert.passkey.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * M1 architecture invariants. Eight rules — see Plan §3.4 (Rule 7: fido2 core purity; Rule 8: no
 * webauthn4j anywhere).
 */
class PackageArchitectureTest {

  private static final String ROOT = "com.crosscert.passkey";

  private static final JavaClasses CLASSES =
      new ClassFileImporter()
          .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
          .importPackages(ROOT);

  // Rule 1: common.* must not depend on domain packages.
  @Test
  void common_does_not_depend_on_domains() {
    noClasses()
        .that()
        .resideInAPackage("..common..")
        .should()
        .dependOnClassesThat()
        .resideInAnyPackage("..tenant..", "..auth..", "..credential..", "..audit..", "..admin..")
        .check(CLASSES);
  }

  // Rule 2: TenantContextHolder must only be touched by tenant.resolver, the JPA multitenancy
  //         infrastructure, read-only diagnostics, or domain services that need to bind the active
  //         tenant for new entity creation paths (e.g. RegistrationService creating a TenantUser).
  //         Controllers never touch it directly — they go through services.
  @Test
  void tenant_context_holder_access_is_restricted() {
    classes()
        .that()
        .haveFullyQualifiedName("com.crosscert.passkey.tenant.context.TenantContextHolder")
        .should()
        .onlyHaveDependentClassesThat()
        .resideInAnyPackage(
            "..tenant.context..",
            "..tenant.resolver..",
            "..tenant.controller..", // DiagnosticsController — read-only inspection
            "..tenant.service..",
            "..credential.service..", // RegistrationService binds tenant id on user creation
            "..credential.challenge..", // ChallengeStore scopes redis keys by current tenant
            "..credential.metadata..", // MdsRevocationScanService binds tenant for per-tenant audit
            "..audit.service..", // AuditService binds tenant id to per-tenant hash chain
            "..ratelimit..", // RateLimitFilter scopes buckets per tenant
            "..admin.security..", // AdminAuthz sets tenant context for admin-scoped endpoints
            "..admin.service..", // AdminTenantService writes audit rows under newly created tenant
            "..auth.apikey.security..", // ApiKeyAuthenticationFilter establishes tenant context
            "..auth.jwt..", // TokenService cross-checks JWT tid claim against ambient tenant
            "..infrastructure.jpa.multitenancy..",
            "..infrastructure.jpa..")
        .check(CLASSES);
  }

  // Rule 3: RP-facing controllers must not call repositories directly. Admin controllers are
  // exempt — read-through list endpoints in the management console need not be wrapped in a
  // throw-away service layer.
  @Test
  void rp_controllers_do_not_call_repositories_directly() {
    noClasses()
        .that()
        .resideInAPackage("..controller..")
        .and()
        .resideOutsideOfPackage("..admin.controller..")
        .should()
        .dependOnClassesThat()
        .resideInAPackage("..repository..")
        .check(CLASSES);
  }

  // Rule 4: MultiTenantConnectionProvider must only be referenced inside its package.
  @Test
  void multi_tenant_provider_is_encapsulated() {
    classes()
        .that()
        .haveSimpleName("TenantConnectionProvider")
        .should()
        .resideInAPackage("..infrastructure.jpa.multitenancy..")
        .check(CLASSES);
  }

  // Rule 5: Controllers may only map to /api/v1/rp, /api/v1/admin, or /_diag prefixes.
  @Test
  void controllers_only_use_reserved_url_prefixes() {
    classes()
        .that()
        .areAnnotatedWith(RequestMapping.class)
        .should(haveReservedPrefix())
        .check(CLASSES);
  }

  // Rule 6: every controller mapped under /api/v1/admin/tenants/{...} must depend on AdminAuthz —
  // a syntactic guard that catches a controller author forgetting to call
  // AdminAuthz.requireTenantAccess / requirePlatformOperator. This is a class-level check, so a
  // controller that imports AdminAuthz but only conditionally calls it still passes; the real
  // safety net is the human-readable AdminAuthz import + a code-review prompt. False positives
  // are zero because every admin endpoint uses the same single entrypoint.
  @Test
  void admin_tenant_controllers_depend_on_admin_authz() {
    classes()
        .that()
        .resideInAPackage("..admin.controller..")
        .and()
        .areAnnotatedWith(RequestMapping.class)
        .should(referenceAdminAuthz())
        .check(CLASSES);
  }

  // Rule 7: the fido2 core is a pure WebAuthn implementation — it must not depend on any domain
  // package, on Spring, or on the application's exception types. Only java.*/javax.* (JCA, LDAP
  // name parsing) + the fido2 package itself + Jackson (clientDataJSON parsing) + nimbus-jose-jwt
  // (MDS3 BLOB JWS verification + android-safetynet JWS verification) are permitted. Milestone B
  // Phase 4 removed webauthn4j entirely from production (see Rule 8); fido2 was already forbidden
  // it. The domain packages are fully qualified under ROOT so the pattern does not accidentally
  // match JDK packages such as javax.security.auth.
  @Test
  void fido2_core_is_pure() {
    noClasses()
        .that()
        .resideInAPackage("..fido2..")
        .should()
        .dependOnClassesThat()
        .resideInAnyPackage(
            ROOT + ".tenant..",
            ROOT + ".auth..",
            ROOT + ".credential..",
            ROOT + ".audit..",
            ROOT + ".admin..",
            ROOT + ".common..",
            ROOT + ".infrastructure..",
            ROOT + ".ratelimit..",
            "org.springframework..")
        .check(CLASSES);
  }

  // Rule 8: production code (everything under ROOT) must not import anything from com.webauthn4j —
  // Milestone B Phase 4 removed the dependency entirely. The fido2 core was already forbidden by
  // Rule 7; this rule extends the ban to credential/admin/etc. domain code, guarding against
  // accidental re-introduction via a future merge that resurrects the dependency.
  @Test
  void no_production_code_depends_on_webauthn4j() {
    noClasses()
        .that()
        .resideInAPackage(ROOT + "..")
        .should()
        .dependOnClassesThat()
        .resideInAnyPackage("com.webauthn4j..")
        .check(CLASSES);
  }

  private static ArchCondition<JavaClass> referenceAdminAuthz() {
    return new ArchCondition<>("reference com.crosscert.passkey.admin.security.AdminAuthz") {
      @Override
      public void check(JavaClass clazz, ConditionEvents events) {
        RequestMapping mapping = clazz.getAnnotationOfType(RequestMapping.class);
        String[] paths = mapping.value().length > 0 ? mapping.value() : mapping.path();
        boolean tenantScoped = false;
        for (String p : paths) {
          if (p.startsWith("/api/v1/admin/tenants/{") || p.startsWith("/api/v1/admin/admins")) {
            // /admins is platform-operator only — requires AdminAuthz too.
            tenantScoped = true;
            break;
          }
        }
        if (!tenantScoped) {
          return; // not in scope of this rule.
        }
        boolean refs =
            clazz.getDirectDependenciesFromSelf().stream()
                .anyMatch(
                    d ->
                        d.getTargetClass()
                            .getFullName()
                            .equals("com.crosscert.passkey.admin.security.AdminAuthz"));
        if (!refs) {
          events.add(
              SimpleConditionEvent.violated(
                  clazz,
                  clazz.getName()
                      + " is mapped under a tenant-scoped admin prefix but does not call"
                      + " AdminAuthz — every such endpoint must guard with requireTenantAccess(...)"
                      + " or requirePlatformOperator()."));
        }
      }
    };
  }

  private static ArchCondition<JavaClass> haveReservedPrefix() {
    return new ArchCondition<>("map to /api/v1/rp/**, /api/v1/admin/** or /_diag/**") {
      @Override
      public void check(JavaClass clazz, ConditionEvents events) {
        RequestMapping mapping = clazz.getAnnotationOfType(RequestMapping.class);
        String[] paths = mapping.value().length > 0 ? mapping.value() : mapping.path();
        if (paths.length == 0) {
          events.add(
              SimpleConditionEvent.violated(
                  clazz, clazz.getName() + " has @RequestMapping with no path"));
          return;
        }
        for (String path : paths) {
          if (!(path.startsWith("/api/v1/rp")
              || path.startsWith("/api/v1/admin")
              || path.startsWith("/_diag"))) {
            events.add(
                SimpleConditionEvent.violated(
                    clazz,
                    clazz.getName()
                        + " maps to "
                        + path
                        + " which is outside the reserved prefixes"));
          }
        }
      }
    };
  }
}
