plugins {
    java
    id("org.springframework.boot") version "3.5.0"
    id("io.spring.dependency-management") version "1.1.7"
    id("com.diffplug.spotless") version "6.25.0"
}

group = "com.crosscert.passkey"
version = "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // core
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")

    // Spring Security — M4: full filter chain (admin session + RP API key).
    implementation("org.springframework.boot:spring-boot-starter-security")

    // OpenAPI spec generation — M4: lets RP devs and the future React SPA discover the API.
    // 2.8.x required for Spring Framework 6.2 (Spring Boot 3.5 ships 6.2.x).
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.9")

    // observability
    // Micrometer Tracing is removed for M1 — it injects OTel-derived traceId/spanId into MDC and
    // overrides our application-controlled traceId. M3 will re-introduce it once we configure
    // propagation so the inbound X-Trace-Id flows through as the OTel trace id.
    runtimeOnly("io.micrometer:micrometer-registry-prometheus")

    // db
    runtimeOnly("org.postgresql:postgresql")
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")

    // webauthn4j — M2 BE-005
    implementation("com.webauthn4j:webauthn4j-core:0.27.0.RELEASE")

    // JWT — M3 BE-011
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    // Password/secret hashing — M3 BE-012 (Argon2 for API keys)
    implementation("de.mkammerer:argon2-jvm:2.11")

    // lombok — API Response Template과 일관성
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
    testCompileOnly("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")

    // test
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.testcontainers:testcontainers:1.20.4")
    testImplementation("org.testcontainers:junit-jupiter:1.20.4")
    testImplementation("org.testcontainers:postgresql:1.20.4")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.3.0")
    testImplementation("org.assertj:assertj-core")
}

configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.testcontainers") {
            useVersion("1.20.4")
        }
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
    // macOS Docker Desktop: socket is under ~/.docker/run/, not /var/run/docker.sock.
    // Set DOCKER_HOST for the forked test JVM before Testcontainers initializes.
    val home = System.getProperty("user.home")
    val desktopSocket = File("$home/.docker/run/docker.sock")
    if (desktopSocket.exists() && System.getenv("DOCKER_HOST") == null) {
        environment("DOCKER_HOST", "unix://${desktopSocket.absolutePath}")
        environment("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", desktopSocket.absolutePath)
    }
    System.getenv("DOCKER_HOST")?.let { environment("DOCKER_HOST", it) }
    System.getenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE")?.let {
        environment("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", it)
    }
}

spotless {
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
