package com.api_server.API.Server.dto.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Data Transfer Object for the JWT tokens
 * TokenDTO is used to send the JWT tokens to the client
 * It contains the access token, refresh token, and expiration time
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AuthTokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("expires_in")
    private Long expiresIn;
    @JsonProperty("refresh_token")
    private String refreshToken;
}

