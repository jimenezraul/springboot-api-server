package com.api_server.API.Server.services;

import com.api_server.API.Server.dto.MessageResponse;
import com.api_server.API.Server.dto.auth.AuthTokenResponse;
import com.api_server.API.Server.dto.auth.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.naming.AuthenticationException;
import java.security.NoSuchAlgorithmException;

public interface AuthService {
    AuthTokenResponse login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) throws AuthenticationException, NoSuchAlgorithmException;

    MessageResponse logout(String refreshToken, HttpServletResponse response) throws NoSuchAlgorithmException;

    AuthTokenResponse refreshToken(String refreshToken, HttpServletRequest request, HttpServletResponse response) throws NoSuchAlgorithmException;
}

