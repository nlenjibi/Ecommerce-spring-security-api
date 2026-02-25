package com.smart_ecomernce_api.smart_ecomernce_api.modules.review;

import com.smart_ecomernce_api.smart_ecomernce_api.security.SecurityRules;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.stereotype.Component;

@Component
public class ReviewSecurityRules implements SecurityRules {
    @Override
    public void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        registry
                .requestMatchers(HttpMethod.GET, "/v1/reviews/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/v1/reviews/**").authenticated()
                .requestMatchers(HttpMethod.PUT, "/v1/reviews/**").authenticated()
                .requestMatchers(HttpMethod.DELETE, "/v1/reviews/**").hasAnyRole("ADMIN", "MANAGER");
    }
}
