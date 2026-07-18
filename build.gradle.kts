plugins {
    id("java-library")
    id("xyz.jpenilla.run-velocity") version "3.0.2"
    id("com.gradleup.shadow") version "9.5.1"
}

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}


dependencies {
    // Velocity API - compileOnly because the proxy provides it at runtime
    compileOnly("com.velocitypowered:velocity-api:4.1.0-SNAPSHOT")
    annotationProcessor("com.velocitypowered:velocity-api:4.1.0-SNAPSHOT")

    // LuckPerms API
    compileOnly("net.luckperms:api:5.5")

    // OAuth2 / OpenID Connect client (discovery, token exchange, ID token validation)
    implementation("com.nimbusds:oauth2-oidc-sdk:11.37.2")

    // In-memory caches with TTL for sessions
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.8")

    // Config file parsing
    implementation("org.yaml:snakeyaml:2.2")

    // Database connectors for JDBC
    implementation("com.mysql:mysql-connector-j:9.7.0")
    implementation("org.mariadb.jdbc:mariadb-java-client:3.5.9")

    // BCrypt package for hashing passwords
    implementation("org.mindrot:jbcrypt:0.4")
}


java {
    toolchain.languageVersion = JavaLanguageVersion.of(25)
}

tasks {
    runVelocity {
        velocityVersion("4.1.0-SNAPSHOT")
    }

    // Relocate bundled dependencies so they can't clash with other plugins' copies of the same libraries loaded on the proxy.
    shadowJar {
        archiveClassifier.set("")
        val pkg = "net.wafflecat.velocityOidcAuth.libs"
        relocate("com.nimbusds", "$pkg.nimbusds")
        relocate("net.minidev", "$pkg.minidev")
        relocate("net.jcip", "$pkg.jcip")
        relocate("com.github.ben-manes.caffeine", "$pkg.caffeine")
        relocate("org.yaml.snakeyaml", "$pkg.snakeyaml")
        relocate("org.mindrot.jbcrypt", "$pkg.jbcrypt")

        // Velocity already ships Gson / Guava / Netty - don't bundle them again.
        exclude("META-INF/maven/**")
        minimize {
            // keep everything we explicitly declared; only strip unused transitive bits
            exclude(dependency("com.nimbusds:oauth2-oidc-sdk:.*"))
            exclude(dependency("com.mysql:mysql-connector-j:.*"))
            exclude(dependency("org.mariadb.jdbc:mariadb-java-client:.*"))
        }
    }

    build {
        dependsOn(shadowJar)
    }
    compileJava {
        options.encoding = "UTF-8"
    }
}
