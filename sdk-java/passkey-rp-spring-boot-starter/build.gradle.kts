plugins {
  id("io.spring.dependency-management") version "1.1.7"
}

dependencyManagement {
  imports {
    mavenBom("org.springframework.boot:spring-boot-dependencies:3.5.0")
  }
}

dependencies {
  api(project(":passkey-rp-sdk-core"))
  api("org.springframework.boot:spring-boot-starter-web")
  api("org.springframework.boot:spring-boot-starter-security")
  compileOnly("org.springframework.boot:spring-boot-starter-actuator")
  compileOnly("io.micrometer:micrometer-core")
  annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

  testImplementation("org.springframework.boot:spring-boot-starter-test")
  testImplementation("org.springframework.security:spring-security-test")
  testImplementation("org.wiremock:wiremock-standalone:3.9.1")
  // Boot 3.5 ships junit-jupiter 5.12 but does not pull the launcher; add it explicitly so the
  // Gradle test runner can boot the engine.
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
