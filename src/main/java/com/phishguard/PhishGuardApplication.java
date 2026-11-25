package com.phishguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Starts the PhishGuard web application.
 *
 * Spring Boot starts an embedded web server (Tomcat), serves the web UI from
 * src/main/resources/static/index.html and exposes the REST API under /api.
 */
@SpringBootApplication
public class PhishGuardApplication {

    public static void main(String[] args) {
        SpringApplication.run(PhishGuardApplication.class, args);
    }
}
