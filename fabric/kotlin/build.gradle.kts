plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    application
}

group = "org.spacesprotocol"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // compileOnly — consumers provide the right variant at runtime:
    //   Android: org.spacesprotocol:libveritas (AAR)
    //   JVM:     org.spacesprotocol:libveritas-jvm (JAR)
    compileOnly("org.spacesprotocol:libveritas-jvm:0.0.0-dev.20260323000045")
    // CLI needs it at runtime
    runtimeOnly("org.spacesprotocol:libveritas-jvm:0.0.0-dev.20260323000045")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    compileOnly("fr.acinq.secp256k1:secp256k1-kmp:0.17.3")
    runtimeOnly("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.17.3")
}

application {
    mainClass.set("org.spacesprotocol.fabric.cli.MainKt")
}

kotlin {
    jvmToolchain(21)
}
