package it.luigibifulco.spring.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import it.luigibifulco.spring.security.application.JWTFilterConfiguration;
import it.luigibifulco.spring.security.authentication.CustomAuthenticationProvider;
import it.luigibifulco.spring.security.authentication.UserPassFilter;
import it.luigibifulco.spring.security.model.DomainUser;
import it.luigibifulco.spring.security.token.PreAuthFilter;
import it.luigibifulco.spring.security.token.TokenService;

@Configuration
@EnableWebSecurity
@EnableScheduling
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(JWTFilterConfiguration.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${backend.admin.role}")
	private String backendAdminRole;

	// @Autowired
	// private TokenAuthenticationFilter tokenAuthenticationFilter;

	// @Autowired
	// private PreAuthFilter preauthfilter;
	//
	// @Autowired
	// private UserPassFilter userPassFilter;

	@Autowired
	private TokenService tokenService;

	@Autowired
	private CustomAuthenticationProvider myAuthProvider;

	@Autowired
	private PreAuthenticatedAuthenticationProvider tokenAuthenticationProvider;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.addFilterBefore(PreAuthFilter(), BasicAuthenticationFilter.class);
		http.addFilterAfter(UsernamePasswordAuthenticationFilter(), PreAuthFilter.class);

		http.authorizeRequests()

				// Authenticate endpoint can be access by anyone
				.antMatchers("/api/login").anonymous().antMatchers("/api/safe/**").authenticated()
		// .and().formLogin()
		// .loginProcessingUrl("api/public/login")

		// All Others will be secure
		;// .hasAnyRole("ADMIN");
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

		auth.authenticationProvider(tokenAuthenticationProvider);
		auth.authenticationProvider(myAuthProvider);
		// auth.authenticationProvider(domainUsernamePasswordAuthenticationProvider())
		// .authenticationProvider(backendAdminUsernamePasswordAuthenticationProvider())
		// .authenticationProvider(tokenAuthenticationProvider());
	}

	// @Bean
	// @ConditionalOnMissingBean(UserPassFilter.class)
	public UserPassFilter UsernamePasswordAuthenticationFilter() throws Exception {
		UserPassFilter filter = new UserPassFilter();
		filter.setAuthenticationManager(authenticationManager());
		filter.setAllowSessionCreation(false);
		filter.setContinueChainBeforeSuccessfulAuthentication(false);
		filter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {

			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				// TODO Auto-generated method stub
				String token = tokenService.generateToken(authentication);
				response.addHeader("X-Auth-Token", token);
				response.setHeader("Content-Type", "application/json");
				response.getWriter().println("{token: " + token + "}");

			}
		});
		return filter;
	}

	// @Bean
	// @ConditionalOnMissingBean(PreAuthFilter.class)
	public PreAuthFilter PreAuthFilter() throws Exception {
		PreAuthFilter filter = new PreAuthFilter(tokenService);
		filter.setAuthenticationManager(authenticationManager());
		filter.setContinueFilterChainOnUnsuccessfulAuthentication(true);
		return filter;
	}

	@Bean
	public PreAuthenticatedAuthenticationProvider preAuthProvider() {
		PreAuthenticatedAuthenticationProvider p = new PreAuthenticatedAuthenticationProvider();
		p.setThrowExceptionWhenTokenRejected(false);
		p.setPreAuthenticatedUserDetailsService(
				new AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>() {

					@Override
					public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token)
							throws UsernameNotFoundException {
						return new DomainUser(token.getPrincipal().toString());
					}
				});
		// p.setUserDetailsChecker(userDetailsChecker);
		return p;
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