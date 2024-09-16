package com.example.usermicroservice.Repositories;

import com.example.usermicroservice.Modules.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    Token save(Token token);
    Optional<Token> findByTokenValueAndDeleted(String tokenValue, boolean deleted);
}
