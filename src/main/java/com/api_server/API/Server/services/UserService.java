package com.api_server.API.Server.services;

import com.api_server.API.Server.dto.user.MeDTO;
import com.api_server.API.Server.models.UserEntity;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserService {
    UserDetails loadUserByUsername(String username);

    UserEntity findUserById(Long id);

    UserEntity findUserByEmail(String email);

    UserEntity getUserById(Long userId);

    UserEntity getCurrentUser();

    MeDTO getMe();
}
