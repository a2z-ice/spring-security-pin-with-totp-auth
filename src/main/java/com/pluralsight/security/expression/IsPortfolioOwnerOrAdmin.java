package com.pluralsight.security.expression;

import static com.pluralsight.security.util.AuthenticationUtil.getUsername;

import com.pluralsight.security.userdetails.MFAUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class IsPortfolioOwnerOrAdmin {

	public boolean check(String username) {
		if(hasRole("ROLE_ADMIN")){
			return true;
		}
		if(hasRole("ROLE_USER")) {
			final MFAUser user = (MFAUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
			return username.equals(user.getUsername());
		}
		return false;
	}

	private boolean hasRole(String role) {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		for(GrantedAuthority authority : authentication.getAuthorities()) {
			if(role.equals(authority.getAuthority())) {
				return true;
			}
		}
		return false;
	}

}
