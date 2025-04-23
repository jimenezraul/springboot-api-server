package com.api_server.API.Server.services.ServiceImpl;

import com.api_server.API.Server.dto.user.MeDTO;
import com.api_server.API.Server.exception.UserNotFoundException;
import com.api_server.API.Server.models.UserEntity;
import com.api_server.API.Server.repository.UserRepository;
import com.api_server.API.Server.services.UserService;
import jakarta.transaction.Transactional;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.text.MessageFormat;

@Service
public class UserServiceImpl implements UserDetailsManager, UserService {

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return (UserDetails) userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        MessageFormat.format("username {0} not found", username)
                ));
    }

    public UserEntity findUserById(Long id) {
        return null;
    }

    @Override
    public UserEntity findUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException(
                "Email is not registered"
        ));
    }

    @Override
    public UserEntity getUserById(Long userId) {
        return userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException(
                MessageFormat.format("User with id {0} not found", userId)
        ));
    }

    @Override
    public UserEntity getCurrentUser() {
        UserEntity user = (UserEntity) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByEmail(user.getEmail()).orElseThrow(() -> new UsernameNotFoundException(
                        MessageFormat.format("User with email {0} not found", user.getEmail())
                )
        );
    }

    @Override
    @Transactional
    public MeDTO getMe() {
        UserEntity currentUser = getCurrentUser();

        return new MeDTO(currentUser);
    }

    @Override
    public void createUser(UserDetails user) {

    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return false;
    }
}