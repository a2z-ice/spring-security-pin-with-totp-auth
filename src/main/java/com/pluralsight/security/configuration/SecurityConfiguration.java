package com.pluralsight.security.configuration;

import com.pluralsight.security.exceptions.AccessDeniedHandlerImpl;
import com.pluralsight.security.filters.TotpAuthenticationFilter;
import com.pluralsight.security.model.Authorities;
import com.pluralsight.security.userdetails.AdditionalAuthenticationDetailSource;
import com.pluralsight.security.userdetails.AdditionalAuthenticationProvider;
import com.pluralsight.security.userdetails.AuthenticationSuccessHandlerImpl;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.AllArgsConstructor;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
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

	@Override
	//@formatter:off
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(totpAuthFilter, UsernamePasswordAuthenticationFilter.class)
				.authorizeRequests()
				.antMatchers(
						"/register", "/login","/login-error",
						"/login-verified","/verify/email")
					.permitAll()
				.antMatchers("/totp-login", "/totp-login-error")
					.hasAnyAuthority(Authorities.TOTP_AUTH_AUTHORITY)
				.anyRequest()
				.hasRole("USER").and()
				.formLogin()
				.loginPage("/login")
				.successHandler(new AuthenticationSuccessHandlerImpl())
				.failureUrl("/login-error")
				.authenticationDetailsSource(new AdditionalAuthenticationDetailSource())
				.and().exceptionHandling().accessDeniedHandler(accessDeniedHandler)
				;

	}
	//@formatter:on
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring()
				.antMatchers("/css/**", "/webjars/**");
	}


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(additionalProvider);
	}

	@Override
	protected UserDetailsService userDetailsService() {
		return userDetailsService;
	}
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		DelegatingPasswordEncoder encoder =  (DelegatingPasswordEncoder)PasswordEncoderFactories.createDelegatingPasswordEncoder();
		encoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
		return encoder;
	}
	@Bean
	public RedirectStrategy getRedirectStrategy() {
		return new DefaultRedirectStrategy();
	}

}
