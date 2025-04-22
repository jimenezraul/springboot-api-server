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

@Log4j2
public class AccessTokenFilter extends OncePerRequestFilter {

    private final JwtAuthenticationProvider accessTokenAuthProvider;
    private final UserRepository userRepository;
    private final JwtToUserConverter jwtToUserConverter;

    public AccessTokenFilter(JwtAuthenticationProvider accessTokenAuthProvider,
                             UserRepository userRepository,
                             JwtToUserConverter jwtToUserConverter) {
        this.accessTokenAuthProvider = accessTokenAuthProvider;
        this.userRepository = userRepository;
        this.jwtToUserConverter = jwtToUserConverter;
    }

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

    private UserEntity getUserFromJwt(Jwt jwt) {
        return userRepository.findByEmail(jwt.getSubject())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
