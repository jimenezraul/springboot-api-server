package com.api_server.API.Server.services;

import com.api_server.API.Server.dto.auth.AuthTokenResponse;
import com.api_server.API.Server.models.RefreshTokenEntity;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

import java.security.NoSuchAlgorithmException;

public interface RefreshTokenService {
    void createRefreshToken(HttpServletRequest request, String token, Long userId) throws NoSuchAlgorithmException;

    RefreshTokenEntity getRefreshToken(String token, Long userId, HttpServletResponse response) throws NoSuchAlgorithmException;

    void deleteRefreshToken(Long id);

    void deleteAllUserRefreshTokens(Long userId);

    void revokeRefreshToken(Long id);

    AuthTokenResponse renewRefreshToken(HttpServletRequest request, HttpServletResponse response, Jwt jwt, Authentication authentication, RefreshTokenEntity token, boolean b) throws NoSuchAlgorithmException;
}