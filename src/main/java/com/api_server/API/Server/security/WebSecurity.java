package com.api_server.API.Server.security;

import com.api_server.API.Server.repository.UserRepository;
import com.api_server.API.Server.security.filter.AccessTokenFilter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Configuration class for Spring Security.
 * This class defines the security settings, including CSRF protection, JWT handling, and authentication providers.
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurity {

    @Autowired
    private JwtToUserConverter jwtToUserConverter;

    @Autowired
    private KeyUtils keyUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    @Lazy
    private UserDetailsManager userDetailsManager;

    @Autowired
    private UserRepository userRepository;

    /**
     * Configures the CSRF token repository to use HTTP session and sets the header name for the CSRF token.
     *
     * @return the CSRF token repository
     */
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }

    /**
     * Configures the security filter chain, including CSRF protection, request authorization, and session management.
     *
     * @param http the HttpSecurity object
     * @return the configured SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf((csrf) -> {
                    csrf
                            .csrfTokenRepository(csrfTokenRepository())
                            .requireCsrfProtectionMatcher(request -> {
                                String method = request.getMethod();
                                // Disable CSRF for /api/v1/webhook
                                if (request.getRequestURI().contains("/api/v1/webhook")) {
                                    return false;
                                }

                                return !HttpMethod.GET.matches(method); // Disable CSRF for GET requests
                            });
                })
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(
                                "/img/**",
                                "/api/v1/auth/**",
                                "/swagger-ui/**",
                                "/api/v1/csrf",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new AccessTokenFilter(this.jwtAccessTokenAuthProvider(), userRepository, jwtToUserConverter), UsernamePasswordAuthenticationFilter.class)
                .oauth2ResourceServer((oauth2) ->
                        oauth2.jwt((jwt) -> jwt.jwtAuthenticationConverter(jwtToUserConverter))
                )
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                );
        return http.build();
    }

    /**
     * Creates a JWT decoder for access tokens using the public key.
     *
     * @return the JWT decoder
     */
    @Bean
    @Primary
    public JwtDecoder jwtAccessTokenDecoder() {
        return createJwtDecoder(keyUtils.getAccessTokenPublicKey());
    }

    /**
     * Creates a JWT decoder for refresh tokens using the public key.
     *
     * @return the JWT decoder
     */
    @Bean
    @Qualifier("jwtRefreshTokenDecoder")
    public JwtDecoder jwtRefreshTokenDecoder() {
        return createJwtDecoder(keyUtils.getRefreshTokenPublicKey());
    }

    /**
     * Helper method to create a JWT decoder with the provided public key.
     *
     * @param publicKey the public key
     * @return the JWT decoder
     */
    private JwtDecoder createJwtDecoder(RSAPublicKey publicKey) {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    /**
     * Creates a JWT encoder for access tokens using the public and private keys.
     *
     * @return the JWT encoder
     */
    @Bean
    @Primary
    public JwtEncoder jwtAccessTokenEncoder() {
        return createJwtEncoder(keyUtils.getAccessTokenPublicKey(), keyUtils.getAccessTokenPrivateKey());
    }

    /**
     * Creates a JWT encoder for refresh tokens using the public and private keys.
     *
     * @return the JWT encoder
     */
    @Bean
    @Qualifier("jwtRefreshTokenEncoder")
    public JwtEncoder jwtRefreshTokenEncoder() {
        return createJwtEncoder(keyUtils.getRefreshTokenPublicKey(), keyUtils.getRefreshTokenPrivateKey());
    }

    /**
     * Helper method to create a JWT encoder with the provided public and private keys.
     *
     * @param publicKey the public key
     * @param privateKey the private key
     * @return the JWT encoder
     */
    private JwtEncoder createJwtEncoder(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        JWK jwk = new RSAKey
                .Builder(publicKey)
                .privateKey(privateKey)
                .build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    /**
     * Creates a JWT authentication provider for access tokens using the JWT decoder.
     *
     * @return the JWT authentication provider
     */
    @Bean
    @Qualifier("jwtAccessTokenAuthProvider")
    public JwtAuthenticationProvider jwtAccessTokenAuthProvider() {
        return createJwtAuthProvider(jwtAccessTokenDecoder());
    }

    /**
     * Creates a JWT authentication provider for refresh tokens using the JWT decoder.
     *
     * @return the JWT authentication provider
     */
    @Bean
    @Qualifier("jwtRefreshTokenAuthProvider")
    public JwtAuthenticationProvider jwtRefreshTokenAuthProvider() {
        return createJwtAuthProvider(jwtRefreshTokenDecoder());
    }

    /**
     * Helper method to create a JWT authentication provider with the provided JWT decoder.
     *
     * @param jwtDecoder the JWT decoder
     * @return the JWT authentication provider
     */
    private JwtAuthenticationProvider createJwtAuthProvider(JwtDecoder jwtDecoder) {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
        provider.setJwtAuthenticationConverter(jwtToUserConverter);
        return provider;
    }

    /**
     * Creates an AccessTokenFilter bean for processing access tokens.
     *
     * @param jwtAuthProvider the JWT authentication provider
     * @param userRepository the user repository
     * @return the AccessTokenFilter
     */
    @Bean
    public AccessTokenFilter accessTokenFilter(@Qualifier("jwtAccessTokenAuthProvider") JwtAuthenticationProvider jwtAuthProvider, UserRepository userRepository) {
        return new AccessTokenFilter(jwtAuthProvider, userRepository, jwtToUserConverter);
    }

    /**
     * Creates a DaoAuthenticationProvider bean for handling DAO-based authentication.
     *
     * @return the DaoAuthenticationProvider
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userDetailsManager);
        return provider;
    }
}