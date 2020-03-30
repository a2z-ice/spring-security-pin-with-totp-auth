package com.pluralsight.security.filters;

import com.pluralsight.security.model.Authorities;
import com.pluralsight.security.service.TOTPService;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@Component
public class TotpAuthenticationFilter extends GenericFilterBean {

    private final TOTPService totpService;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private String onSuccessUrl = "/portfolio";
    private String onFailureUrl = "/totp-login-error";

    public TotpAuthenticationFilter(TOTPService totpService){
        this.totpService = totpService;
    }

    //formatter:off
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String code = obtainCode(request);
        if(code == null || !requiresTotpAuthentication(authentication)){
            filterChain.doFilter(request, response);
            return;
        }

        if(codeIsValid(authentication.getName(), code)) {
            final Set<String> authorities = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
            authorities.remove(Authorities.TOTP_AUTH_AUTHORITY);
            authorities.add(Authorities.ROLE_USER);
            authentication = new UsernamePasswordAuthenticationToken(
                    authentication.getName(),
                    authentication.getCredentials(),
                    buildAuthorities(authorities)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            redirectStrategy.sendRedirect(
                    (HttpServletRequest) request,
                    (HttpServletResponse) response,
                    onSuccessUrl);

        } else {
            redirectStrategy.sendRedirect((HttpServletRequest)request, (HttpServletResponse)response, onFailureUrl);
        }
    }


    private Collection<? extends GrantedAuthority> buildAuthorities(Set<String> authorities) {
        List<GrantedAuthority> authList = new ArrayList<GrantedAuthority>(1);
        for(String authority : authorities) {
            authList.add(new SimpleGrantedAuthority(authority));
        }
        return authList;
    }

    private boolean codeIsValid(String username, String code) {
            return code != null && totpService.verifyCode(username, Integer.valueOf(code));
    }

    private boolean requiresTotpAuthentication(Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        Set<String> authorities = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
        boolean hasTotpAuthority = authorities.contains(Authorities.TOTP_AUTH_AUTHORITY);
        return hasTotpAuthority && authentication.isAuthenticated();
    }
    //formatter:on

    private String obtainCode(ServletRequest request) {
        return request.getParameter("totp_code");
    }
}
