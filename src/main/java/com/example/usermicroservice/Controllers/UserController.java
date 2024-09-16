package com.example.usermicroservice.Controllers;

import com.example.usermicroservice.Dtos.*;
import com.example.usermicroservice.Exceptions.InvalidUserFoundExcpetion;
import com.example.usermicroservice.Exceptions.WrongPasswordException;
import com.example.usermicroservice.Modules.Token;
import com.example.usermicroservice.Modules.User;
import com.example.usermicroservice.Services.UserService;
import jakarta.persistence.Entity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {
    private UserService userService;
    UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public UserDto signUp(@RequestBody UserSignUpRequestDto userSignUpRequestDto) {
        User user=userService.getUserSignUp(userSignUpRequestDto.getName(),userSignUpRequestDto.getEmail(),userSignUpRequestDto.getPassword());
        UserDto userDto=new UserDto();
        userDto.setName(user.getName());
        userDto.setEmail(user.getEmail());
        userDto.setVerified(user.isVerified());
        return userDto;
    }

    @PostMapping("/login")
    public Token logIn(@RequestBody UserLoginRequestDto userLoginRequestDto) throws InvalidUserFoundExcpetion, WrongPasswordException {
        return userService.getUserLogIn(userLoginRequestDto.getEmail(),userLoginRequestDto.getPassword());

    }

    @PostMapping("/logout/{tokenValue}")
    public void logout(@PathVariable String tokenValue) {
        userService.getLogOut(tokenValue);
    }

    @PostMapping("/validate/{tokenValue}")
    public UserDto validateToken(@PathVariable String tokenValue) {
        User user=userService.getValidateToken(tokenValue);
        UserDto userDto=new UserDto();
        userDto.setName(user.getName());
        userDto.setEmail(user.getEmail());
        userDto.setVerified(user.isVerified());
        return userDto;
    }
}
