package com.api_server.API.Server.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity(name = "refresh_token")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class RefreshTokenEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "revoked", nullable = false)
    private Boolean revoked = false;

    @Column(name = "issued_at", nullable = false)
    private LocalDateTime issuedAt = LocalDateTime.now();

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    public RefreshTokenEntity(String token, UserEntity user, String ipAddress, String userAgent) {
        this.token = token;
        this.user = user;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.expiresAt = LocalDateTime.now().plusDays(30);
    }

    public RefreshTokenEntity(RefreshTokenEntity refreshTokenEntity) {
        this.id = refreshTokenEntity.getId();
        this.token = refreshTokenEntity.getToken();
        this.user = refreshTokenEntity.getUser();
        this.expiresAt = refreshTokenEntity.getExpiresAt();
        this.revoked = refreshTokenEntity.getRevoked();
        this.issuedAt = refreshTokenEntity.getIssuedAt();
        this.ipAddress = refreshTokenEntity.getIpAddress();
        this.userAgent = refreshTokenEntity.getUserAgent();
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiresAt);
    }

    public boolean isRevoked() {
        return this.revoked;
    }

    public void revoke() {
        this.revoked = true;
    }
}
