package com.example.restApi.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import com.example.restApi.Security.JWT.AuthEntryPointJwt;

import static org.springframework.security.config.Customizer.withDefaults;
import com.example.restApi.Security.JWT.AuthTokenFilter;
import com.example.restApi.Security.JWT.JwtLogoutHandler;
import com.example.restApi.Security.Services.UserDetailsServiceImpl;

@Configuration
@EnableMethodSecurity
// WebSecurityConfigurerAdapter is the crux of our security implementation.
// It provides HttpSecurity configurations to configure cors, csrf, session
// management, rules for protected resources.
// We can also extend and customize the default configuration that contains the
// elements below.
public class WebSecurityConfig {

  @Autowired
  UserDetailsServiceImpl userDetailsServiceImpl;

  @Autowired
  private AuthEntryPointJwt unauthorizedHandler;

  @Bean
  public AuthTokenFilter authenticationJWtTokenFilter() {
    return new AuthTokenFilter();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
    authenticationProvider.setUserDetailsService(userDetailsServiceImpl);
    authenticationProvider.setPasswordEncoder(passwordEncoder());
    return authenticationProvider;

  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
  }

  // This is essential to make sure that the Spring Security session registry is
  // notified when the session is destroyed.
  @Bean
  public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.cors(withDefaults()).csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(
            authorize -> authorize.requestMatchers("/api/auth/signun",
                "/api/auth/signin").permitAll()
                .requestMatchers("/api/test/**").authenticated())
        .exceptionHandling(handling -> handling.authenticationEntryPoint(unauthorizedHandler))
        .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .invalidSessionUrl("/invalidSession.html"));
    // traitement Authentication request is processed by an AuthenticationProvider
    http.authenticationProvider(authenticationProvider());
    http.addFilterBefore(authenticationJWtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    // http.logout().logoutUrl("/api/auth/logout")

    // handle error 401 UNAUTHORIZED
    // .exceptionHandling()
    // .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
    return http.build();
  }

  @Bean
  public JwtLogoutHandler jwtLogoutHandler() {
    return new JwtLogoutHandler();
  }
}
