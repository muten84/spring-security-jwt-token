package it.luigibifulco.spring.security.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import it.luigibifulco.spring.security.model.DomainUser;

@RestController
// @PreAuthorize("hasRole('ADMIN')")
public class SampleController {

	@RequestMapping(value = "api/safe/currentUser")
	@Secured(value = { "ROLE_USER" })
	// @PreAuthorize ("hasRole('ROLE_USER')")
	public DomainUser getCurrentUser(@AuthenticationPrincipal String domainUser) {
		return new DomainUser(domainUser);
	}

	@RequestMapping(value = "api/safe/adminUser")
	@Secured(value = { "ROLE_ADMIN" })
	// @PreAuthorize ("hasRole('ROLE_ADMIN')")
	public DomainUser getAdminUser(@AuthenticationPrincipal String domainUser) {
		return new DomainUser(domainUser);
	}
}
