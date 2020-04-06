package com.hendisantika.springbootoauth2demo.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 9/21/17
 * Time: 5:42 AM
 * To change this template use File | Settings | File Templates.
 */

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
    @Value("${resource.id:spring-boot-application}")
    private String resourceId;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        // @formatter:off
        resources.resourceId(resourceId);
        // @formatter:on
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.requestMatcher(new OAuthRequestedMatcher())
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .anyRequest().authenticated();
        // @formatter:on
    }

    private static class OAuthRequestedMatcher implements RequestMatcher {
        public boolean matches(HttpServletRequest request) {
            String auth = request.getHeader("Authorization");
            // Determine if the client request contained an OAuth Authorization
            boolean haveOauth2Token = (auth != null) && auth.startsWith("Bearer");
            boolean haveAccessToken = request.getParameter("access_token")!=null;
            return haveOauth2Token || haveAccessToken;
        }
    }
}
