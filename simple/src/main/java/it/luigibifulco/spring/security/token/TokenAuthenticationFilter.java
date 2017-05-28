package it.luigibifulco.spring.security.token;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class TokenAuthenticationFilter extends GenericFilterBean {

	private static final String BEARER = "Bearer ";
	private final TokenService tokenService;

	@Autowired
	public TokenAuthenticationFilter(TokenService tokenService) {
		this.tokenService = tokenService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;

		Optional<String> token = Optional.ofNullable(httpRequest.getHeader("Authorization"))
				.filter(s -> s.length() > BEARER.length() && s.startsWith(BEARER))
				.map(s -> s.substring(BEARER.length(), s.length()));

		Optional<Authentication> authentication = tokenService.verifyToken(token);
		if (authentication.isPresent()) {
			SecurityContextHolder.getContext().setAuthentication(authentication.get());
		}

		chain.doFilter(httpRequest, response);
	}

}
