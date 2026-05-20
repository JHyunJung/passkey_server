plugins {
  id("com.diffplug.spotless") version "6.25.0" apply false
}

allprojects {
  group = "com.crosscert.passkey"
  version = "0.1.0-SNAPSHOT"

  repositories {
    mavenCentral()
  }
}

subprojects {
  if (name == "passkey-rp-sdk-bom") return@subprojects

  // The demo app is a runnable Spring Boot module, not a published library — it brings its own
  // Spring Boot plugin (which applies `java`). Skip the library/publish wiring; keep only the
  // shared Java toolchain + spotless via the dedicated block below.
  if (name == "passkey-rp-demo") {
    apply(plugin = "com.diffplug.spotless")
    extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
      java {
        target("src/**/*.java")
        googleJavaFormat("1.22.0")
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
      }
    }
    plugins.withId("java") {
      extensions.configure<JavaPluginExtension> {
        toolchain { languageVersion = JavaLanguageVersion.of(17) }
      }
    }
    tasks.named("check") { dependsOn("spotlessCheck") }
    return@subprojects
  }

  apply(plugin = "java-library")
  apply(plugin = "maven-publish")
  apply(plugin = "com.diffplug.spotless")

  extensions.configure<JavaPluginExtension> {
    toolchain {
      languageVersion = JavaLanguageVersion.of(17)
    }
    withSourcesJar()
    withJavadocJar()
  }

  tasks.withType<Test>().configureEach {
    useJUnitPlatform()
  }

  tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).addBooleanOption("Xdoclint:none", true)
  }

  extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
      target("src/**/*.java")
      googleJavaFormat("1.22.0")
      removeUnusedImports()
      trimTrailingWhitespace()
      endWithNewline()
    }
  }

  tasks.named("check") {
    dependsOn("spotlessCheck")
  }
}
