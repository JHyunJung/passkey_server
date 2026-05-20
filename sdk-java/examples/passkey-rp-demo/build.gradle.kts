plugins {
  java
  id("org.springframework.boot") version "3.5.0"
  id("io.spring.dependency-management") version "1.1.7"
}

dependencies {
  // The whole point of the demo: the starter brings ceremony endpoints, JWT auth, the security
  // filter chain and exception handling — the demo itself writes almost no passkey code.
  implementation(project(":passkey-rp-spring-boot-starter"))
  implementation("org.springframework.boot:spring-boot-starter-web")
}

// Runnable app, not a published artifact.
tasks.named<Jar>("jar") { enabled = false }
