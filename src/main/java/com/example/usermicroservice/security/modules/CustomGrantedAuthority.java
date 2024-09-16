package com.example.usermicroservice.security.modules;

import com.example.usermicroservice.Modules.Role;
import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {
    private String authority;


    public CustomGrantedAuthority(Role role) {
        this.authority = role.getRoleName();
    }
    @Override
    public String getAuthority() {
        return authority;
    }
}
