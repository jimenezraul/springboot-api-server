package com.api_server.API.Server.security;

import com.api_server.API.Server.dto.auth.AuthTokenResponse;
import com.api_server.API.Server.models.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Component responsible for generating JWT tokens for authentication and activation purposes.
 * This class provides methods to create access tokens, refresh tokens, and activation tokens
 * based on user information and authentication details.
 *
 * Annotations:
 * - @Component: Marks this class as a Spring-managed component, allowing it to be automatically
 *   detected and registered as a bean.
 */
@Component
public class TokenGenerator {
    @Autowired
    private JwtEncoder accessTokenEncoder;

    @Autowired
    @Qualifier("jwtRefreshTokenEncoder")
    private JwtEncoder refreshTokenEncoder;

    /**
     * Creates a JWT token with the specified user details, encoder, issue time, duration, and time unit.
     *
     * @param user The user for whom the token is being created.
     * @param encoder The encoder used to generate the token.
     * @param duration The duration for which the token is valid.
     * @param unit The unit of time for the duration (e.g., minutes, hours, days).
     * @return The generated JWT token as a string.
     */
    private String createToken(UserEntity user, JwtEncoder encoder, long duration, ChronoUnit unit) {
        String issuer = "Name of the app";
        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plus(duration, unit))
                .subject(user.getEmail())
                .claim("id", user.getUserId())
                .claim("roles", user.getRoles())
                .claim("first_name", user.getGivenName())
                .claim("last_name", user.getFamilyName())
                .claim("profile_picture", user.getImageUrl())
                .build();

        return encoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    public String createActivationToken(UserEntity user) {
        long activationTokenExpiresIn = 24;
        return createToken(user, accessTokenEncoder, activationTokenExpiresIn, ChronoUnit.HOURS);
    }

    public String createAccessToken(Authentication authentication) {
        UserEntity user = (UserEntity) authentication.getPrincipal();
        long accessTokenExpiresIn = 15;
        return createToken(user, accessTokenEncoder, accessTokenExpiresIn, ChronoUnit.MINUTES);
    }

    private String createRefreshToken(Authentication authentication) {
        UserEntity user = (UserEntity) authentication.getPrincipal();
        long refreshTokenExpiresIn = 30;
        return createToken(user, refreshTokenEncoder, refreshTokenExpiresIn, ChronoUnit.DAYS);
    }

    public AuthTokenResponse createToken(Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof UserEntity user)) {
            throw new BadCredentialsException(
                    MessageFormat.format("principal {0} is not of User type", authentication.getPrincipal().getClass())
            );
        }

        AuthTokenResponse authTokenResponse = new AuthTokenResponse();
        Instant now = Instant.now();

        authTokenResponse.setAccessToken(createAccessToken(authentication));
        authTokenResponse.setExpiresIn(now.plus(15, ChronoUnit.MINUTES).toEpochMilli());
        String refreshToken;
        if (authentication.getCredentials() instanceof Jwt jwt) {
            Instant expiresAt = jwt.getExpiresAt();
            long daysUntilExpired = Duration.between(now, expiresAt).toDays();
            refreshToken = (daysUntilExpired < 7) ? createRefreshToken(authentication) : jwt.getTokenValue();
        } else {
            refreshToken = createRefreshToken(authentication);
        }
        authTokenResponse.setRefreshToken(refreshToken);

        return authTokenResponse;
    }
}