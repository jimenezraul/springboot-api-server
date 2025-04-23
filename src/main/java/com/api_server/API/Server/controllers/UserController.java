package com.api_server.API.Server.controllers;

import com.api_server.API.Server.dto.user.MeDTO;
import com.api_server.API.Server.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/me")
    @PreAuthorize("hasRole('ROLE_STAFF')")
    public ResponseEntity<MeDTO> getMe() {
        MeDTO me = userService.getMe();
        return ResponseEntity.ok(me);
    }
}
