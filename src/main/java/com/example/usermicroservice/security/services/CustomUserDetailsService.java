package com.example.usermicroservice.security.services;

import com.example.usermicroservice.Modules.User;
import com.example.usermicroservice.Repositories.UserRepository;
import com.example.usermicroservice.security.modules.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

public class CustomUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository=userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User>optionalUser=userRepository.findByEmail(username);
        if(!optionalUser.isPresent()){
            throw new UsernameNotFoundException("User not found");
        }

        User user=optionalUser.get();

        UserDetails userDetails=new CustomUserDetails(user);



    }
}
