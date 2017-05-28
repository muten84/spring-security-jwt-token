package it.luigibifulco.spring.security.authentication;

import javax.annotation.PostConstruct;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import it.luigibifulco.spring.security.token.TokenService;

//@Component
public class UserPassFilter extends UsernamePasswordAuthenticationFilter {

	public TokenService tokenService;

	// @Autowired
	// private AuthenticationManager manager;

	@PostConstruct
	public void setAuthManager() {

		// this.setAuthenticationManager(manager);
	}

}
