package it.luigibifulco.spring.security.config;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import it.luigibifulco.spring.security.authentication.CustomAuthenticationProvider;
import it.luigibifulco.spring.security.token.TokenAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableScheduling
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${backend.admin.role}")
	private String backendAdminRole;

	@Autowired
	private TokenAuthenticationFilter tokenAuthenticationFilter;

	@Autowired
	private CustomAuthenticationProvider myAuthProvider;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.addFilterBefore(tokenAuthenticationFilter, BasicAuthenticationFilter.class);

		http.authorizeRequests()

				// Authenticate endpoint can be access by anyone
				.antMatchers("/api/login").anonymous()

				// All Others will be secure
				.antMatchers("/api/safe/**").authenticated();// .hasAnyRole("ADMIN");
	}

	// private String[] actuatorEndpoints() {
	// return new String[] { ApiController.AUTOCONFIG_ENDPOINT,
	// ApiController.BEANS_ENDPOINT,
	// ApiController.CONFIGPROPS_ENDPOINT, ApiController.ENV_ENDPOINT,
	// ApiController.MAPPINGS_ENDPOINT,
	// ApiController.METRICS_ENDPOINT, ApiController.SHUTDOWN_ENDPOINT };
	// }

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(myAuthProvider);
		// auth.authenticationProvider(domainUsernamePasswordAuthenticationProvider())
		// .authenticationProvider(backendAdminUsernamePasswordAuthenticationProvider())
		// .authenticationProvider(tokenAuthenticationProvider());
	}

	// @Bean
	// public CacheTokenService tokenService() {
	// return new CacheTokenService();
	// }

	// @Bean
	// public ExternalServiceAuthenticator someExternalServiceAuthenticator() {
	// return new SomeExternalServiceAuthenticator();
	// }
	//
	// @Bean
	// public AuthenticationProvider
	// domainUsernamePasswordAuthenticationProvider() {
	// return new DomainUsernamePasswordAuthenticationProvider(tokenService(),
	// someExternalServiceAuthenticator());
	// }
	//
	// @Bean
	// public AuthenticationProvider
	// backendAdminUsernamePasswordAuthenticationProvider() {
	// return new BackendAdminUsernamePasswordAuthenticationProvider();
	// }
	//
	// @Bean
	// public AuthenticationProvider tokenAuthenticationProvider() {
	// return new TokenAuthenticationProvider(tokenService());
	// }

	@Bean
	public AuthenticationEntryPoint unauthorizedEntryPoint() {
		return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	}
}