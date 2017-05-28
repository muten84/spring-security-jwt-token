package it.luigibifulco.spring.security.token;

import java.util.Optional;

import org.springframework.security.core.Authentication;

public interface TokenService {

  String generateToken(Authentication authentication);

  Optional<Authentication> verifyToken(Optional<String> token);

}