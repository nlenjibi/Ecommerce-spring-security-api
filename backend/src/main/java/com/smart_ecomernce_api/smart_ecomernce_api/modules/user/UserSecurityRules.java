package com.smart_ecomernce_api.smart_ecomernce_api.modules.user;

import com.smart_ecomernce_api.smart_ecomernce_api.security.SecurityRules;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.stereotype.Component;

@Component
public class UserSecurityRules implements SecurityRules {
    @Override
    public void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        registry
                .requestMatchers(HttpMethod.POST, "/v1/users/register", "/v1/users/auth/login", "/v1/users/auth/refresh").permitAll()
                .requestMatchers(HttpMethod.GET, "/v1/users/**").authenticated()
                .requestMatchers(HttpMethod.POST, "/v1/users/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers(HttpMethod.PUT, "/v1/users/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers(HttpMethod.PATCH, "/v1/users/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers(HttpMethod.DELETE, "/v1/users/**").hasRole("ADMIN");
    }
}
