package com.api_server.API.Server.repository;

import com.api_server.API.Server.enums.RoleEnum;
import com.api_server.API.Server.models.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    RoleEntity findByName(RoleEnum name);
}
