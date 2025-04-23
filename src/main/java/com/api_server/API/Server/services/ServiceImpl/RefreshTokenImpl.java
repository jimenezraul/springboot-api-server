package com.api_server.API.Server.services.ServiceImpl;

import com.api_server.API.Server.dto.auth.AuthTokenResponse;
import com.api_server.API.Server.exception.UserNotFoundException;
import com.api_server.API.Server.models.RefreshTokenEntity;
import com.api_server.API.Server.models.UserEntity;
import com.api_server.API.Server.repository.RefreshTokenRepository;
import com.api_server.API.Server.security.TokenGenerator;
import com.api_server.API.Server.services.RefreshTokenService;
import com.api_server.API.Server.services.UserService;
import com.api_server.API.Server.utils.Cookies;
import com.api_server.API.Server.utils.SHA256Hasher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Service
public class RefreshTokenImpl implements RefreshTokenService {
    @Autowired
    private UserService userService;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private TokenGenerator tokenGenerator;
    @Autowired
    private Cookies cookies;

    @Override
    public void createRefreshToken(HttpServletRequest request, String token, Long userId) throws NoSuchAlgorithmException {
        UserEntity user = userService.getUserById(userId);
        String ipAddress = request.getRemoteAddr(); // Get the IP address
        String userAgent = request.getHeader("User-Agent"); // Get the User-Agent header
        String hashToken = SHA256Hasher.hash(token); // Hash the token
        refreshTokenRepository.save(new RefreshTokenEntity(hashToken, user, ipAddress, userAgent));
    }

    @Override
    public RefreshTokenEntity getRefreshToken(String token, Long userId, HttpServletResponse response) throws NoSuchAlgorithmException {
        // get all tokens for the user that are not revoked
        List<RefreshTokenEntity> refreshTokenEntities = refreshTokenRepository.findByUserIdAndRevokedFalse(userId);

        for (RefreshTokenEntity refreshTokenEntity : refreshTokenEntities) {
            // Revoke expired refresh tokens
            if (refreshTokenEntity.isExpired()) {
                refreshTokenEntity.revoke();
                refreshTokenRepository.save(refreshTokenEntity);
            }
        }

        // Hashing the token to match the stored token
        String hashToken = SHA256Hasher.hash(token);

        // Match the provided token with existing valid (non-revoked) refresh tokens
        for (RefreshTokenEntity refreshTokenEntity : refreshTokenEntities) {
            if (refreshTokenEntity.getToken().equals(hashToken) && !refreshTokenEntity.isRevoked()) {
                return new RefreshTokenEntity(refreshTokenEntity);
            }
        }

        cookies.deleteCookie(response);
        throw new UserNotFoundException("Refresh token not found");

    }

    @Override
    public void deleteRefreshToken(Long id) {
        refreshTokenRepository.deleteById(id);
    }

    @Override
    public void deleteAllUserRefreshTokens(Long userId) {
        List<RefreshTokenEntity> refreshTokenEntities = refreshTokenRepository.findByUserId(userId);
        for (RefreshTokenEntity refreshTokenEntity : refreshTokenEntities) {
            refreshTokenRepository.deleteById(refreshTokenEntity.getId());
        }
    }

    @Override
    public void revokeRefreshToken(Long id) {
        RefreshTokenEntity refreshTokenEntity = refreshTokenRepository.findById(id).orElse(null);
        if (refreshTokenEntity != null) {
            refreshTokenEntity.revoke();
            refreshTokenRepository.save(refreshTokenEntity);
        }
    }

    @Override
    public AuthTokenResponse renewRefreshToken(HttpServletRequest request, HttpServletResponse response, Jwt jwt, Authentication authentication, RefreshTokenEntity token, boolean isApp) throws NoSuchAlgorithmException {
        Instant now = Instant.now();
        Instant expiresAt = jwt.getExpiresAt();
        Duration duration = Duration.between(now, expiresAt);
        long daysUntilExpired = duration.toDays();
        AuthTokenResponse tokens = tokenGenerator.createToken(authentication);

        if (daysUntilExpired < 7) {
            revokeRefreshToken(token.getId());
            createRefreshToken(request, tokens.getRefreshToken(), Long.valueOf(jwt.getSubject()));
        }

        if (!isApp) {
            cookies.setTokenCookies(response, tokens.getAccessToken(), tokens.getRefreshToken());
        }

        return tokens;
    }
}

