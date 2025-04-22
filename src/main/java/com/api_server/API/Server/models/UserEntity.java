package com.api_server.API.Server.models;

import com.api_server.API.Server.enums.LoginProvider;
import com.api_server.API.Server.utils.CustomIDGenerator;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Entity(name = "User")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class UserEntity implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "user_id", nullable = false, unique = true)
    private String userId = CustomIDGenerator.generateCustomID("usr_");
    private String username;
    private String password;
    private String email;
    private String name;
    @Column(name = "given_name")
    private String givenName;
    @Column(name = "family_name")
    private String familyName;
    @Column(name = "image_url")
    private String imageUrl;
    // Ban User
    @Column(name = "is_banned")
    private Boolean isBanned = false;

    @Enumerated(value = EnumType.STRING)
    LoginProvider provider;

    @Column(name = "created_at")
    LocalDateTime createdAt = LocalDateTime.now();

    public UserEntity(String username, String password, String email, String name, String givenName, String familyName,  String imageUrl, LoginProvider provider) {
        this.username = username.toLowerCase();
        this.password = password;
        this.email = email;
        this.name = name;
        this.givenName = givenName;
        this.familyName = familyName;
        this.imageUrl = imageUrl;
        this.provider = provider;
    }

    @ToString.Exclude
    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.MERGE)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Collection<RoleEntity> roles = new ArrayList<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
