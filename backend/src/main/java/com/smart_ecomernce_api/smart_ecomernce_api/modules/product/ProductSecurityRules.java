package com.smart_ecomernce_api.smart_ecomernce_api.modules.product;

import com.smart_ecomernce_api.smart_ecomernce_api.security.SecurityRules;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.stereotype.Component;

@Component
public class ProductSecurityRules implements SecurityRules {
    @Override
    public void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        registry
                .requestMatchers(HttpMethod.GET, "/v1/products/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/v1/featured", "/v1/new", "/v1/discounted").permitAll()
                .requestMatchers(HttpMethod.POST, "/v1/products/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers(HttpMethod.PUT, "/v1/products/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers(HttpMethod.PATCH, "/v1/products/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers(HttpMethod.DELETE, "/v1/products/**").hasRole("ADMIN");
    }
}
