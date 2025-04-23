package com.api_server.API.Server.dto.user;

import com.api_server.API.Server.models.UserEntity;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collection;
import java.util.stream.Collectors;


/**
 * Data Transfer Object for the current user
 * MeDTO is used to send the current user's information to the client
 * It contains the user's id, first name, last name, email, profile image, and roles
 */

public record MeDTO(
        String id,
        @JsonProperty("first_name") String givenName,
        @JsonProperty("last_name") String familyName,
        String email,
        @JsonProperty("profile_image") String imageUrl,
        Collection<RoleDTO> roles
) {
    public MeDTO(UserEntity user) {
        this(
                user.getUserId(),
                user.getGivenName(),
                user.getFamilyName(),
                user.getEmail(),
                user.getImageUrl(),
                user.getRoles().stream().map(role -> new RoleDTO(role.getName())).collect(Collectors.toList())
        );
    }
}

