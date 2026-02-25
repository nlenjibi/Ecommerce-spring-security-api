package com.smart_ecomernce_api.smart_ecomernce_api.security;

import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@AllArgsConstructor
@Getter
public class OAuth2UserPrincipal implements OAuth2User {

    private final User user;
    private final Map<String, Object> attributes;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return user.getEmail();
    }

    public String getEmail() {
        return user.getEmail();
    }

    public Long getId() {
        return user.getId();
    }
}
