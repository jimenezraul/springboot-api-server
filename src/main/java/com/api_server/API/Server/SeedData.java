package com.api_server.API.Server;

import com.api_server.API.Server.enums.RoleEnum;
import com.api_server.API.Server.models.RoleEntity;
import com.api_server.API.Server.models.UserEntity;
import com.api_server.API.Server.repository.RoleRepository;
import com.api_server.API.Server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class SeedData implements CommandLineRunner {
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Value("${spring.jpa.hibernate.ddl-auto}")
    private String ddlAuto;

    @Override
    public void run(String... args) throws Exception {
        // Check if ddl-auto is set to 'create'
        if ("create".equalsIgnoreCase(ddlAuto)) {
            loadDummyData();
        } else {
            System.out.println("Skipping seeding data as ddl-auto is not set to 'create'");
        }
    }

    private void loadDummyData() throws Exception {
        RoleEntity adminRole = new RoleEntity(RoleEnum.ROLE_ADMIN);
        RoleEntity ownerRole = new RoleEntity(RoleEnum.ROLE_OWNER);
        RoleEntity staffRole = new RoleEntity(RoleEnum.ROLE_STAFF);
        RoleEntity userRole = new RoleEntity(RoleEnum.ROLE_USER);
        RoleEntity ROLE_ADMIN = roleRepository.save(adminRole);
        RoleEntity ROLE_USER = roleRepository.save(userRole);
        RoleEntity ROLE_STAFF = roleRepository.save(staffRole);
        RoleEntity ROLE_OWNER = roleRepository.save(ownerRole);

        // create a owner
        UserEntity owner = new UserEntity();
        owner.setGivenName("John");
        owner.setFamilyName("Doe");
        owner.setEmail("johndoe@example.com");
        owner.setUsername("johndoe@example.com");
        owner.setImageUrl("https://example.com/johndoe.jpg");
        owner.setPassword(passwordEncoder.encode("password"));
        UserEntity owner1 = userRepository.save(owner);


        owner1.getRoles().add(ROLE_OWNER);
        owner1.getRoles().add(ROLE_STAFF);
        owner1.getRoles().add(ROLE_ADMIN);

        userRepository.save(owner1);
    }
}
