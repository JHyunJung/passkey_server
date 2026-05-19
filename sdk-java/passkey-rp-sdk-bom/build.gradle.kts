plugins {
  `java-platform`
  `maven-publish`
}

dependencies {
  constraints {
    api("com.crosscert.passkey:passkey-rp-sdk-core:${project.version}")
    api("com.crosscert.passkey:passkey-rp-spring-boot-starter:${project.version}")
  }
}
