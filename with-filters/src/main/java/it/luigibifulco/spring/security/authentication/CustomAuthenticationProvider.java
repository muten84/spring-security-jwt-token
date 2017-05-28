package it.luigibifulco.spring.security.authentication;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.google.common.base.Optional;

import it.luigibifulco.spring.security.model.DomainUser;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Optional<Object> username = Optional.of(authentication.getPrincipal());
		Optional<Object> password = Optional.of(authentication.getCredentials());

		if (!username.isPresent() || !password.isPresent()) {
			throw new BadCredentialsException("Invalid Domain User Credentials");
		}
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
		updatedAuthorities.add(authority);
		UsernamePasswordAuthenticationToken tok = new UsernamePasswordAuthenticationToken(
				new DomainUser(username.get().toString()),
				password.get(), updatedAuthorities);
		tok.setDetails(new DomainUser(username.get().toString()));
		// tok.setAuthenticated(true);
		return tok;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
