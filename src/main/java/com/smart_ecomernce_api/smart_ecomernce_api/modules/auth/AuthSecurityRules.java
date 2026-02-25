package com.smart_ecomernce_api.smart_ecomernce_api.modules.auth;

import com.smart_ecomernce_api.smart_ecomernce_api.security.SecurityRules;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.stereotype.Component;

@Component
public class AuthSecurityRules implements SecurityRules {
    @Override
    public void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        registry
            .requestMatchers("/v1/auth/register",
                            "/v1/auth/login",
                            "/v1/auth/refresh",
                            "/v1/auth/logout",
                            "/v1/auth/password/change",
                            "/v1/auth/account/lock",
                            "/v1/auth/account/unlock",
                            "/v1/auth/security/stats",
                            "/v1/auth/security/blacklist/cleanup").permitAll()

            .requestMatchers("/v1/auth/oauth2/success",
                            "/v1/auth/oauth2/failure",
                            "/v1/auth/oauth2/exchange",
                            "/v1/auth/oauth2/providers",
                            "/v1/auth/oauth2/token",
                            "/v1/auth/oauth2/**",
                            "/oauth2/**",
                            "/login/oauth2/**").permitAll()
            .requestMatchers("/v1/auth/account/lock",
                            "/v1/auth/account/unlock",
                            "/v1/auth/security/**").hasRole("ADMIN");
    }
}
