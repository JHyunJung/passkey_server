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

/** M1 architecture invariants. Five rules — see Plan §3.4. */
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
            "..audit.service..", // AuditService binds tenant id to per-tenant hash chain
            "..ratelimit..", // RateLimitFilter scopes buckets per tenant
            "..admin.security..", // AdminAuthz sets tenant context for admin-scoped endpoints
            "..admin.service..", // AdminTenantService writes audit rows under newly created tenant
            "..auth.apikey.security..", // ApiKeyAuthenticationFilter establishes tenant context
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
