package com.api_server.API.Server.security.filter;

import com.api_server.API.Server.models.UserEntity;
import com.api_server.API.Server.repository.UserRepository;
import com.api_server.API.Server.security.JwtToUserConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Filter for processing access tokens in incoming HTTP requests.
 * This filter extracts access tokens from cookies or headers, validates them, and sets the authentication context.
 */
@Log4j2
public class AccessTokenFilter extends OncePerRequestFilter {

    private final JwtAuthenticationProvider accessTokenAuthProvider;
    private final UserRepository userRepository;
    private final JwtToUserConverter jwtToUserConverter;

    /**
     * Constructor for AccessTokenFilter.
     *
     * @param accessTokenAuthProvider the JWT authentication provider for validating access tokens
     * @param userRepository the repository for accessing user data
     * @param jwtToUserConverter the converter for transforming JWTs into user authentication objects
     */
    public AccessTokenFilter(JwtAuthenticationProvider accessTokenAuthProvider,
                             UserRepository userRepository,
                             JwtToUserConverter jwtToUserConverter) {
        this.accessTokenAuthProvider = accessTokenAuthProvider;
        this.userRepository = userRepository;
        this.jwtToUserConverter = jwtToUserConverter;
    }

    /**
     * Processes incoming HTTP requests to extract and validate access tokens.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param filterChain the filter chain to pass the request and response to the next filter
     * @throws ServletException if an error occurs during request processing
     * @throws IOException if an I/O error occurs during request processing
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            Optional<String> accessToken = parseAccessToken(request);

            if (accessToken.isPresent()) {
                Authentication authentication = this.getUserByAccessToken(accessToken.get());

                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

        } catch (Exception e) {
            log.error("Cannot set authentication", e);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts the access token from the HTTP request.
     * The token can be found in cookies or the Authorization header.
     *
     * @param request the HTTP request
     * @return an Optional containing the access token if found, or an empty Optional otherwise
     */
    private Optional<String> parseAccessToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }

        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return Optional.of(header.substring(7));
        }

        return Optional.empty();
    }

    /**
     * Retrieves the user associated with the given access token and creates an authentication object.
     *
     * @param accessToken the access token
     * @return a UsernamePasswordAuthenticationToken representing the authenticated user, or null if the user is banned
     */
    private UsernamePasswordAuthenticationToken getUserByAccessToken(String accessToken) {
        Authentication authentication = accessTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(accessToken));
        Jwt jwt = (Jwt) authentication.getCredentials();

        UserEntity user = getUserFromJwt(jwt);

        if (Boolean.TRUE.equals(user.getIsBanned())) {
            log.warn("Banned user attempted access: {}", user.getEmail());
            return null;
        }

        return jwtToUserConverter.convert(jwt);
    }

    /**
     * Retrieves the user entity from the JWT.
     *
     * @param jwt the JWT containing user information
     * @return the UserEntity associated with the JWT
     * @throws UsernameNotFoundException if the user is not found in the repository
     */
    private UserEntity getUserFromJwt(Jwt jwt) {
        return userRepository.findByEmail(jwt.getSubject())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}