package com.api_server.API.Server.security;

import com.api_server.API.Server.exception.UserNotFoundException;
import com.api_server.API.Server.models.UserEntity;
import com.api_server.API.Server.repository.UserRepository;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Converter class that transforms a JWT (JSON Web Token) into a Spring Security
 * `UsernamePasswordAuthenticationToken`. This is used to authenticate users based
 * on the information contained in the JWT.
 *
 * Annotations:
 * - @Component: Marks this class as a Spring-managed component, allowing it to be
 *   automatically detected and registered as a bean.
 */
@Component
public class JwtToUserConverter implements Converter<Jwt, UsernamePasswordAuthenticationToken> {

    /**
     * Repository for accessing user data from the database.
     * It is automatically injected by Spring.
     */
    private final UserRepository userRepository;

    /**
     * Constructor for `JwtToUserConverter` that allows dependency injection of the
     * `UserRepository`.
     *
     * @param userRepository The repository used to fetch user data from the database.
     */
    public JwtToUserConverter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Converts a JWT into a `UsernamePasswordAuthenticationToken` by extracting the
     * user information and roles from the database.
     *
     * @param jwt The JWT containing the user's information.
     * @return A `UsernamePasswordAuthenticationToken` containing the authenticated
     *         user and their roles.
     * @throws UserNotFoundException If the user is not found in the database.
     */
    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt jwt) {
        // Fetch the user from the database using the email (subject) from the JWT
        UserEntity userFromDb = userRepository.findByEmail(jwt.getSubject())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Convert the user's roles into a collection of GrantedAuthority objects
        Collection<? extends GrantedAuthority> authorities = userFromDb.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        // Return the authentication token containing the user, JWT, and authorities
        return new UsernamePasswordAuthenticationToken(userFromDb, jwt, authorities);
    }
}
