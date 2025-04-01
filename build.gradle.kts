plugins {
    id("java")
//    kotlin("jvm") version "1.9.22"
//     kotlin("plugin.allopen") version "1.9.22"
     id("io.quarkus")
}


group = "io.github.renegrob.oidc"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    mavenLocal()
}

val quarkusPlatformGroupId: String by project
val quarkusPlatformArtifactId: String by project
val quarkusPlatformVersion: String by project

val infinispanEmbeddedVersion: String by project
val protostreamVersion: String by project;

dependencies {
    implementation(enforcedPlatform("${quarkusPlatformGroupId}:${quarkusPlatformArtifactId}:${quarkusPlatformVersion}"))

    // Core Quarkus
    implementation("io.quarkus:quarkus-rest-jackson")
    implementation("io.quarkus:quarkus-config-yaml")
    implementation("io.quarkus:quarkus-container-image-docker")

    // Security & JWT
    implementation("io.quarkus:quarkus-oidc")
    implementation("io.quarkus:quarkus-security")
    implementation("io.quarkus:quarkus-smallrye-jwt")
    implementation("io.quarkus:quarkus-smallrye-jwt-build")

    // Session Management with Infinispan
    implementation("io.quarkiverse.infinispan:quarkus-infinispan-embedded:${infinispanEmbeddedVersion}")
    annotationProcessor("org.infinispan.protostream:protostream-processor:${protostreamVersion}")
    compileOnly("org.infinispan.protostream:protostream-processor:${protostreamVersion}")

    // Util
    implementation("io.quarkus:quarkus-arc")
    implementation("com.nimbusds:nimbus-jose-jwt:9.37.3")

    // Testing
    testImplementation("io.quarkus:quarkus-junit5")
    testImplementation("io.rest-assured:rest-assured")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

//allOpen {
//    annotation("jakarta.enterprise.context.ApplicationScoped")
//    annotation("jakarta.ws.rs.Path")
//    annotation("jakarta.persistence.Entity")
//}

tasks.withType<Test> {
    systemProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-parameters")
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}