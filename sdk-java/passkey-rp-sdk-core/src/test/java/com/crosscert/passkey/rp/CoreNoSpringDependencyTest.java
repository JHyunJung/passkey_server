package com.crosscert.passkey.rp;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

/**
 * ArchUnit guard: the core SDK must not depend on Spring or jakarta.servlet. Non-Spring callers
 * (CLI tools, plain-Jetty apps, Quarkus, etc.) need to consume {@code passkey-rp-sdk-core}
 * standalone.
 */
class CoreNoSpringDependencyTest {

  @Test
  void core_has_no_spring_or_servlet_dependency() {
    JavaClasses classes =
        new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("com.crosscert.passkey.rp");

    noClasses()
        .should()
        .dependOnClassesThat()
        .resideInAnyPackage("org.springframework..", "jakarta.servlet..")
        .check(classes);
  }
}
