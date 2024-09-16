package com.example.usermicroservice.Dtos;

import com.example.usermicroservice.Modules.Role;
import lombok.Generated;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserDto {
    private String name;
    private String email;
    private boolean isVerified;
}
