package com.api_server.API.Server.controllers;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for handling CSRF-related endpoints.
 * Provides an endpoint to retrieve the CSRF token.
 */
@RestController
@RequestMapping("/api/v1")
public class CsrfController {

    /**
     * Endpoint to retrieve the CSRF token.
     * This method returns the CSRF token for the current session.
     *
     * @param token the CSRF token provided by Spring Security
     * @return the CSRF token
     */
    @GetMapping("/csrf")
    public CsrfToken getCsrf(CsrfToken token) {
        return token;
    }
}
