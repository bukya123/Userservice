package com.example.usermicroservice.Modules;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity
public class User extends BaseModel{
    private String name;
    private String email;
    private String password;
    private String phone;
    @ManyToMany(fetch = FetchType.EAGER)
    private List<Role> roles;
    private boolean isVerified;
}
