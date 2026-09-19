package com.hendisantika.springbootoauth2demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 9/21/17
 * Time: 5:44 AM
 * To change this template use File | Settings | File Templates.
 */

@RestController
@RequestMapping("/resources")
public class ResourceController {

    // hasRole() already prepends the ROLE_ prefix, so the role names are unprefixed here.
    @PreAuthorize("hasRole('USER')")
    @GetMapping("user")
    public String helloUser() {
        return "hello user";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("admin")
    public String helloAdmin() {
        return "hello admin";
    }

    @PreAuthorize("hasRole('CLIENT')")
    @GetMapping("client")
    public String helloClient() {
        return "hello user authenticated by normal client";
    }

    @PreAuthorize("hasRole('TRUSTED_CLIENT')")
    @GetMapping("trusted_client")
    public String helloTrustedClient() {
        return "hello user authenticated by trusted client";
    }

    // Deliberately reports the name rather than the principal object: for HTTP Basic that
    // object is a UserDetails, whose encoded password would otherwise be serialised out.
    @GetMapping("principal")
    public Map<String, Object> getPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return Map.of("name", authentication.getName());
    }

    @GetMapping("roles")
    public List<String> getRoles() {
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}
