package com.api_server.API.Server.repository;

import com.api_server.API.Server.models.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    List<RefreshTokenEntity> findByUserId(Long userId);

    List<RefreshTokenEntity> findByUserIdAndRevokedFalse(Long userId);
}
