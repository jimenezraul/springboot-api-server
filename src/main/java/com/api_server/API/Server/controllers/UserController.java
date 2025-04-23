package com.api_server.API.Server.controllers;

import com.api_server.API.Server.dto.user.MeDTO;
import com.api_server.API.Server.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for handling user-related endpoints.
 * Provides an endpoint to retrieve information about the currently authenticated user.
 */
@RestController
@RequestMapping("/api/v1")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Endpoint to retrieve information about the currently authenticated user.
     * This endpoint is restricted to users with the "ROLE_STAFF" role.
     *
     * @return a ResponseEntity containing the user's information as a MeDTO object
     */
    @GetMapping("/me")
    @PreAuthorize("hasRole('ROLE_STAFF')")
    public ResponseEntity<MeDTO> getMe() {
        MeDTO me = userService.getMe();
        return ResponseEntity.ok(me);
    }
}
