package com.api_server.API.Server.controllers;

import com.api_server.API.Server.dto.MessageResponse;
import com.api_server.API.Server.dto.auth.AuthTokenResponse;
import com.api_server.API.Server.dto.auth.LoginRequest;
import com.api_server.API.Server.services.ServiceImpl.AuthServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.hibernate.annotations.Parameter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletResponse;

import javax.naming.AuthenticationException;
import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    @Autowired
    private AuthServiceImpl authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletResponse response, @Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) throws AuthenticationException, NoSuchAlgorithmException {
        AuthTokenResponse tokens = authService.login(loginRequest, response, request);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @CookieValue(name = "refreshToken") String refreshToken, HttpServletResponse response) throws NoSuchAlgorithmException {
        MessageResponse messageResponse = authService.logout(refreshToken, response);
        return ResponseEntity.ok(messageResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthTokenResponse> refreshToken(@CookieValue(name = "refreshToken") String refreshToken, HttpServletRequest request, HttpServletResponse response) throws NoSuchAlgorithmException {
        AuthTokenResponse tokens = authService.refreshToken(refreshToken, request, response);
        return ResponseEntity.ok(tokens);
    }

    ///
    /// TODO: POST /register – Register a new user
    ///

    ///
    /// TODO: POST /verify-email – Verify user email via token
    ///

    ///
    /// TODO: POST /resend-verification – Resend email verification link
    ///

    ///
    /// TODO: POST /forgot-password – Initiate password reset
    ///

    ///
    /// TODO: POST /reset-password – Reset password with token
    ///

    ///
    /// TODO: POST /change-password – Authenticated password change
    ///

}
