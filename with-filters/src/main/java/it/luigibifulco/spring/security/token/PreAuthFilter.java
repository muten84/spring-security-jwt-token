package it.luigibifulco.spring.security.token;

import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

//@Component
public class PreAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

	private static final String BEARER = "Bearer ";

	// @Autowired
	private TokenService tokenService;

	// @Autowired
	// private AuthenticationManager manager;

	public PreAuthFilter(TokenService tokenService) {
		this.tokenService = tokenService;
	}

	@PostConstruct
	public void setAuthManager() {
		this.setContinueFilterChainOnUnsuccessfulAuthentication(true);
		// this.setAuthenticationManager(manager);
	}

	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		HttpServletRequest httpRequest = (HttpServletRequest) request;

		Optional<String> token = Optional.ofNullable(httpRequest.getHeader("Authorization"))
				.filter(s -> s.length() > BEARER.length() && s.startsWith(BEARER))
				.map(s -> s.substring(BEARER.length(), s.length()));

		Optional<Authentication> authentication = tokenService.verifyToken(token);
		if (authentication.isPresent())
			return authentication.get().getPrincipal();
		return null;

	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		HttpServletRequest httpRequest = (HttpServletRequest) request;

		Optional<String> token = Optional.ofNullable(httpRequest.getHeader("Authorization"))
				.filter(s -> s.length() > BEARER.length() && s.startsWith(BEARER))
				.map(s -> s.substring(BEARER.length(), s.length()));
		return token;
	}

}
