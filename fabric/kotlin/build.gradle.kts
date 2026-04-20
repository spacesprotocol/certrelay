import java.util.Base64

plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    `maven-publish`
    signing
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
    compileOnly("org.spacesprotocol:libveritas-jvm:0.1.2")
    // CLI needs it at runtime
    runtimeOnly("org.spacesprotocol:libveritas-jvm:0.1.2")

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

java {
    withSourcesJar()
    withJavadocJar()
}

val libVersion: String = project.findProperty("libVersion") as? String ?: version.toString()

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "org.spacesprotocol"
            artifactId = "fabric"
            version = libVersion

            from(components["java"])

            pom {
                name.set("fabric")
                description.set("Fabric client for the certrelay network (JVM)")
                url.set("https://github.com/spacesprotocol/certrelay")

                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://github.com/spacesprotocol/certrelay/blob/main/LICENSE")
                    }
                }

                developers {
                    developer {
                        id.set("spacesprotocol")
                        name.set("spacesprotocol")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/spacesprotocol/certrelay.git")
                    developerConnection.set("scm:git:ssh://github.com/spacesprotocol/certrelay.git")
                    url.set("https://github.com/spacesprotocol/certrelay")
                }
            }
        }
    }

    repositories {
        maven {
            name = "CentralPortal"
            url = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
            credentials(HttpHeaderCredentials::class) {
                name = "Authorization"
                val user = System.getenv("CENTRAL_PORTAL_USERNAME") ?: ""
                val pass = System.getenv("CENTRAL_PORTAL_PASSWORD") ?: ""
                value = "Bearer " + Base64.getEncoder().encodeToString("$user:$pass".toByteArray())
            }
            authentication {
                create<HttpHeaderAuthentication>("header")
            }
        }
    }
}

signing {
    val signingKey = System.getenv("GPG_SIGNING_KEY")
    val signingPassword = System.getenv("GPG_PASSPHRASE")
    if (signingKey != null && signingPassword != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["release"])
    }
}
