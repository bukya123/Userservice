package com.example.usermicroservice.Dtos;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.bind.annotation.ResponseStatus;

@Getter
@Setter
public class UserSignUpResponseDto {
    private String username;
}
