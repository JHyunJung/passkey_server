rootProject.name = "passkey-rp-sdk-parent"

include(":passkey-rp-sdk-core")
include(":passkey-rp-spring-boot-starter")
include(":passkey-rp-sdk-bom")

include(":examples:passkey-rp-demo")
project(":examples:passkey-rp-demo").projectDir = file("examples/passkey-rp-demo")
