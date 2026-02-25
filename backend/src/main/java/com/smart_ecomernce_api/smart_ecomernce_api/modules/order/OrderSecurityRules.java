package com.smart_ecomernce_api.smart_ecomernce_api.modules.order;

import com.smart_ecomernce_api.smart_ecomernce_api.security.SecurityRules;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.stereotype.Component;

@Component
public class OrderSecurityRules implements SecurityRules {
    @Override
    public void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        registry
                .requestMatchers(HttpMethod.GET, "/v1/orders/my-orders").authenticated()
                .requestMatchers(HttpMethod.GET, "/v1/orders/**").authenticated()
                .requestMatchers(HttpMethod.POST, "/v1/orders/**").authenticated()
                .requestMatchers(HttpMethod.PUT, "/v1/orders/**").hasAnyRole("ADMIN", "MANAGER", "STAFF")
                .requestMatchers(HttpMethod.PATCH, "/v1/orders/**").hasAnyRole("ADMIN", "MANAGER", "STAFF")
                .requestMatchers(HttpMethod.DELETE, "/v1/orders/**").hasRole("ADMIN");
    }
}
