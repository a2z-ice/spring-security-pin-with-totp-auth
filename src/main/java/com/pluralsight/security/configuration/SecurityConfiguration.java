package com.pluralsight.security.configuration;

import com.pluralsight.security.exceptions.AccessDeniedHandlerImpl;
import com.pluralsight.security.filters.TotpAuthenticationFilter;
import com.pluralsight.security.model.Authorities;
import com.pluralsight.security.userdetails.AdditionalAuthenticationDetailSource;
import com.pluralsight.security.userdetails.AdditionalAuthenticationProvider;
import com.pluralsight.security.userdetails.AuthenticationSuccessHandlerImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private AdditionalAuthenticationProvider additionalProvider;
	@Autowired
	@Qualifier("userDetailsServiceNoSql")
	private UserDetailsService userDetailsService;
	@Autowired
	private TotpAuthenticationFilter totpAuthFilter;
	@Autowired
	private AccessDeniedHandlerImpl accessDeniedHandler;
	@Autowired
	private PersistentTokenRepository persistentTokenRepository;
	@Autowired
	@Qualifier("oauth2authSuccessHandler")
	private AuthenticationSuccessHandler oauth2authSuccessHandler;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	//@formatter:off
		http
			.addFilterBefore(totpAuthFilter, UsernamePasswordAuthenticationFilter.class)
				.exceptionHandling()
				.accessDeniedHandler(accessDeniedHandler)
				.and()
				.formLogin().loginPage("/login")
					.successHandler(new AuthenticationSuccessHandlerImpl())
					.failureUrl("/login-error")
					.authenticationDetailsSource(new AdditionalAuthenticationDetailSource())
					.and()
				.rememberMe()
					.authenticationSuccessHandler(new AuthenticationSuccessHandlerImpl())
					.tokenRepository(persistentTokenRepository)
					.and()
				.oauth2Login()
					.loginPage("/login")
					.successHandler(oauth2authSuccessHandler)
					.and()
				.authorizeRequests()
					.mvcMatchers(
							"/register", "/login","/login-error",
							"/login-verified","/verify/email").permitAll()
					.mvcMatchers("/totp-login", "/totp-login-error").hasAnyAuthority(Authorities.TOTP_AUTH_AUTHORITY)
					.mvcMatchers("/portfolio**","/account/**").hasRole("USER")
					.mvcMatchers(HttpMethod.POST,"/support/admin/**")
						//if user loggedin anonymously or remember-me the fullyAuthenticated method return false
//						.fullyAuthenticated() // No role assigned to assign role do following
						.access("isFullyAuthenticated() and hasRole('ADMIN')")
					.mvcMatchers("/support/**").hasAnyRole("USER", "ADMIN")
					.mvcMatchers("/api/users").hasRole("ADMIN")
					.mvcMatchers("/api/users/{username}/portfolio")
						//access allow spring security expression so all expression syntax will be allowed
						//logical(&& || !), relational(!= == <= >=), conditional and regex operators
						//#username reference to {username} of url /api/users/{username}/portfolio
						//.access("hasRole('ADMIN') || hasRole('USER') && #username == principal.username")
						// the above approach is hard to read the most readable option is to create a bean object like following
						//Bean approach, where bean name started with lowercase. Now the control is yours
						.access("@isPortfolioOwnerOrAdmin.check(#username)")

					.anyRequest().denyAll()

				//oauth2Login create authenticated principal with  USER Role(ROLE_USER) to customize roles use
				// .and().oauth2Login().authorizationEndpoint().authorizationRequestRepository(authorizationRequestRepository)
				;
	//@formatter:on
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring()
				.antMatchers("/css/**", "/webjars/**");
	}


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(additionalProvider);
	}

	//Used by remember-me
	@Override
	protected UserDetailsService userDetailsService() {
		return userDetailsService;
	}
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		DelegatingPasswordEncoder encoder =  (DelegatingPasswordEncoder)PasswordEncoderFactories.createDelegatingPasswordEncoder();
		//encoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
		return encoder;
	}
	@Bean
	public RedirectStrategy getRedirectStrategy() {
		return new DefaultRedirectStrategy();
	}

}
