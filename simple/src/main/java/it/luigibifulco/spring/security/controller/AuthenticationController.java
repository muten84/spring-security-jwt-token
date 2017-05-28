package it.luigibifulco.spring.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import it.luigibifulco.spring.security.token.TokenService;

@RestController
public class AuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private TokenService tokenService;

	@RequestMapping(value = "api/login", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public String authenticate(@RequestBody LoginRequest loginRequest) {
		// return "This is just for in-code-documentation purposes and Rest API
		// reference documentation." +
		// "Servlet will never get to this point as Http requests are processed
		// by AuthenticationFilter." +
		// "Nonetheless to authenticate Domain User POST request with
		// X-Auth-Username and X-Auth-Password headers " +
		// "is mandatory to this URL. If username and password are correct valid
		// token will be returned (just json string in response) " +
		// "This token must be present in X-Auth-Token header in all requests
		// for all other URLs, including logout." +
		// "Authentication can be issued multiple times and each call results in
		// new ticket.";

		// check here to verify generated token http://calebb.net/
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		String token = tokenService.generateToken(authentication);
		return token;
		// return new LoginResponse(token);
	}
}
