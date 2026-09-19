package com.hendisantika.springbootoauth2demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.LinkedHashSet;

/**
 * Application security: who the demo users are, and how the protected
 * /resources/** endpoints accept either HTTP Basic or a bearer JWT.
 * <p>
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 9/21/17
 * Time: 5:43 AM
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    /**
     * CSRF protection is left at its default (on): it guards the session the login form creates,
     * and every endpoint here is a GET, which CSRF never challenges.
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(HttpMethod.OPTIONS).permitAll()
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                // Needed by the authorization_code flow: the user signs in here before consenting.
                .formLogin(Customizer.withDefaults())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        return new InMemoryUserDetailsManager(
                User.withUsername("user").password(passwordEncoder.encode("password")).roles("USER").build(),
                User.withUsername("app_client").password(passwordEncoder.encode("nopass")).roles("USER").build(),
                User.withUsername("admin").password(passwordEncoder.encode("password")).roles("ADMIN").build()
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Grants both {@code SCOPE_*} authorities from the standard {@code scope} claim and
     * {@code ROLE_*} authorities from the custom {@code roles} claim written by
     * {@link AuthorizationServerConfiguration#jwtTokenCustomizer()}, so that the same
     * {@code @PreAuthorize("hasRole(...)")} rules apply to Basic and bearer callers alike.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopeAuthorities = new JwtGrantedAuthoritiesConverter();

        JwtGrantedAuthoritiesConverter roleAuthorities = new JwtGrantedAuthoritiesConverter();
        roleAuthorities.setAuthoritiesClaimName("roles");
        roleAuthorities.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new LinkedHashSet<>(scopeAuthorities.convert(jwt));
            authorities.addAll(roleAuthorities.convert(jwt));
            return authorities;
        });
        return converter;
    }
}
