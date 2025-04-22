package com.api_server.API.Server.models;

import com.api_server.API.Server.enums.RoleEnum;
import jakarta.persistence.*;
import lombok.*;

@Entity(name = "Role")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class RoleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "name")
    private RoleEnum name;

    public RoleEntity(RoleEntity role) {
        this.id = role.getId();
        this.name = role.getName();
    }

    public RoleEntity(RoleEnum role) {
        this.name = role;
    }
}
