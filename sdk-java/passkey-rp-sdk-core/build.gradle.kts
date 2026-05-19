dependencies {
  api("com.fasterxml.jackson.core:jackson-databind:2.17.2")
  api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.17.2")
  api("com.nimbusds:nimbus-jose-jwt:9.40")
  api("org.slf4j:slf4j-api:2.0.13")

  // Optional — used only when the host app already exposes Micrometer. compileOnly keeps the core
  // dep set minimal for non-Micrometer consumers.
  compileOnly("io.micrometer:micrometer-core:1.13.2")

  testImplementation(platform("org.junit:junit-bom:5.10.3"))
  testImplementation("org.junit.jupiter:junit-jupiter")
  testImplementation("org.assertj:assertj-core:3.26.0")
  testImplementation("org.mockito:mockito-core:5.12.0")
  testImplementation("org.wiremock:wiremock-standalone:3.9.1")
  testImplementation("io.micrometer:micrometer-core:1.13.2")
  testImplementation("com.tngtech.archunit:archunit-junit5:1.3.0")
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
