package com.api_server.API.Server.services.ServiceImpl;

import com.api_server.API.Server.dto.MessageResponse;
import com.api_server.API.Server.dto.auth.AuthTokenResponse;
import com.api_server.API.Server.dto.auth.LoginRequest;
import com.api_server.API.Server.models.RefreshTokenEntity;
import com.api_server.API.Server.models.UserEntity;
import com.api_server.API.Server.security.TokenGenerator;
import com.api_server.API.Server.services.AuthService;
import com.api_server.API.Server.services.RefreshTokenService;
import com.api_server.API.Server.services.UserService;
import com.api_server.API.Server.utils.Cookies;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.security.NoSuchAlgorithmException;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private DaoAuthenticationProvider daoAuthenticationProvider;

    @Autowired
    private TokenGenerator tokenGenerator;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private UserService userService;

    @Autowired
    @Qualifier("jwtRefreshTokenAuthProvider")
    private JwtAuthenticationProvider refreshTokenAuthProvider;
    @Autowired
    private Cookies cookies;

    @Override
    public AuthTokenResponse login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) throws AuthenticationException, NoSuchAlgorithmException {
        // Authenticate the user
        Authentication authentication = daoAuthenticationProvider.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password())
        );

        // Retrieve the authenticated user
        UserEntity user = (UserEntity) authentication.getPrincipal();

        // Check if the user is banned
        if (user.getIsBanned()) {
            throw new AuthenticationException("Your account has been banned");
        }

        // Optionally check if email is verified
        // if (!user.getIsEmailVerified()) {
        //     throw new AuthenticationException("Email not verified");
        // }

        // Generate tokens (access token and refresh token)
        AuthTokenResponse tokens = tokenGenerator.createToken(authentication);

        // Create and store the refresh token
        refreshTokenService.createRefreshToken(request, tokens.getRefreshToken(), user.getId());

        // Optionally update the user's last login (can be done asynchronously)
//        userService.updateLastLogin(user.getId());

        cookies.setTokenCookies(response, tokens.getAccessToken(), tokens.getRefreshToken());

        return tokens;
    }

    @Override
    public MessageResponse logout(String refreshToken, HttpServletResponse response) throws NoSuchAlgorithmException {
        Authentication authentication = refreshTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(refreshToken));
        Jwt jwt = (Jwt) authentication.getCredentials();
        UserEntity user = userService.findUserByEmail(jwt.getSubject());

        // Retrieve and revoke the refresh token
        RefreshTokenEntity token = refreshTokenService.getRefreshToken(refreshToken, user.getId(), response);
        refreshTokenService.revokeRefreshToken(token.getId());

        // Delete the token cookies
        cookies.deleteCookie(response);

        return new MessageResponse("Logged out successfully", "OK");
    }

    @Override
    public AuthTokenResponse refreshToken(String refreshToken, HttpServletRequest request, HttpServletResponse response) throws NoSuchAlgorithmException {
        Authentication authentication = refreshTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(refreshToken));
        Jwt jwt = (Jwt) authentication.getCredentials();

        // Retrieve user and refresh token
        UserEntity user = userService.findUserByEmail(jwt.getSubject());
        RefreshTokenEntity token = refreshTokenService.getRefreshToken(refreshToken, user.getId(), response);

        // Renew the refresh token and return a new pair of tokens

        return refreshTokenService.renewRefreshToken(request, response, jwt, authentication, token, false);
    }
}

