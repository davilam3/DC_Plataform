plugins {
	java
	id("org.springframework.boot") version "4.0.0"
	id("io.spring.dependency-management") version "1.1.7"
}

group = "ec.edu.ups.icc"
version = "0.0.1-SNAPSHOT"
description = "Demo project for Spring Boot"


java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(17)
	}
}

repositories {
	mavenCentral()
}

dependencies {
// Spring Boot Starters
    implementation ("org.springframework.boot:spring-boot-starter-web")
    implementation ("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation ("org.springframework.boot:spring-boot-starter-security")
    implementation ("org.springframework.boot:spring-boot-starter-validation")
    implementation ("org.springframework.boot:spring-boot-starter-mail")
    implementation ("org.springframework.boot:spring-boot-starter-thymeleaf")
    
    // Database
    runtimeOnly ("org.postgresql:postgresql")
    
    // JWT
    implementation ("io.jsonwebtoken:jjwt-api:0.12.3")
    runtimeOnly ("io.jsonwebtoken:jjwt-impl:0.12.3")
    runtimeOnly ("io.jsonwebtoken:jjwt-jackson:0.12.3")
    
    // Jackson for Java 8+ dates
    implementation ("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    
    // Utilities
    compileOnly ("org.projectlombok:lombok")
    annotationProcessor ("org.projectlombok:lombok")
    
    // Testing
    testImplementation ("org.springframework.boot:spring-boot-starter-test")
    testImplementation ("org.springframework.security:spring-security-test")
    
    // Swagger/OpenAPI
    implementation ("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0")
    
    // PDF Generation
    implementation ("com.itextpdf:itext7-core:7.2.5")
    
    // Excel Generation
    implementation ("org.apache.poi:poi-ooxml:5.2.3")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
