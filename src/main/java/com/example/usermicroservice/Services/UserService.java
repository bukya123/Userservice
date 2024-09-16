package com.example.usermicroservice.Services;

import com.example.usermicroservice.Exceptions.InvalidUserFoundExcpetion;
import com.example.usermicroservice.Exceptions.WrongPasswordException;
import com.example.usermicroservice.Modules.Token;
import com.example.usermicroservice.Modules.User;
import com.example.usermicroservice.Repositories.TokenRepository;
import com.example.usermicroservice.Repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Service
public class UserService {
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private TokenRepository tokenRepository;
    UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, TokenRepository tokenRepository) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.tokenRepository = tokenRepository;
    }
    public User getUserSignUp(String username, String email,String password) {
        Optional<User> optionalUser=userRepository.findByEmail(email);
        if(optionalUser.isPresent()) {
            return optionalUser.get();
        }
        User user = new User();
        user.setEmail(email);
        user.setName(username);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        // to add Bcrypted password u need to add dependency in spring--> springboot starter security (search in maven)
        return userRepository.save(user);
    }

    public Token getUserLogIn(String email, String password) throws InvalidUserFoundExcpetion, WrongPasswordException {
        Optional<User>OptionalUser=userRepository.findByEmail(email);
        if(OptionalUser.isEmpty()) {
            throw new InvalidUserFoundExcpetion("User not found.Please signup");
        }

        if(!bCryptPasswordEncoder.matches(password, OptionalUser.get().getPassword())) {
            throw new WrongPasswordException("Wrong Password");
        }

        Token token = generateToken(OptionalUser.get());
        return tokenRepository.save(token);
    }

    private Token generateToken(User user) {
        LocalDate currentTime=LocalDate.now();    //this will give u a current time;
        LocalDate currentTimePlusThirtyDays=currentTime.plusDays(30);
        Date expiryDate=Date.from(currentTimePlusThirtyDays.atStartOfDay(ZoneId.systemDefault()).toInstant());

        Token token=new Token();
        token.setExpiryAt(expiryDate);
        token.setUser(user);
        token.setDeleted(false);
        // to generate random string value--> we need install apache commons lang dependency
        token.setTokenValue(RandomStringUtils.randomAlphanumeric(128));

        return token;
    }

    public void getLogOut(String token){
        Optional<Token>optionalToken=tokenRepository.findByTokenValueAndDeleted(token,false);
        if(optionalToken.isEmpty()) {
            throw new RuntimeException("Token not found");
        }
        Token token1=optionalToken.get();
        if(!token1.getTokenValue().equals(token)){
            throw new RuntimeException("Wrong Token");
        }
        token1.setDeleted(true);
        tokenRepository.save(token1);
    }

    public User getValidateToken(String tokenValue){
        Optional<Token>optionalToken=tokenRepository.findByTokenValueAndDeleted(tokenValue,false);
        if(optionalToken.isEmpty()) {
            throw new RuntimeException("Token not found");
        }
        Token token1=optionalToken.get();
        return token1.getUser();
    }

}
