package com.smart_ecomernce_api.smart_ecomernce_api.security;

import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.Role;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.User;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        
        String registrationId = userRequest.getClientRegistration().getRegistrationId().toLowerCase();
        log.info("OAuth2 login from provider: {}", registrationId);
        
        String email = getEmail(registrationId, oAuth2User);
        String name = getName(registrationId, oAuth2User);
        String avatar = getAvatar(registrationId, oAuth2User);
        
        if (email == null) {
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        User user = userRepository.findByEmail(email).orElse(null);
        
        if (user == null) {
            user = createNewUser(registrationId, email, name);
            user = userRepository.save(user);
            log.info("Created new OAuth2 user: {} via {}", email, registrationId);
        } else {
            updateExistingUser(user, registrationId, name, avatar);
            user = userRepository.save(user);
        }

        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
        attributes.put("email", email); // Ensure email is set with fallback if null
        attributes.put("user", user);
        attributes.put("provider", registrationId);

        return new org.springframework.security.oauth2.core.user.DefaultOAuth2User(
                java.util.Collections.singletonList(
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + user.getRole().name())
                ),
                attributes,
                "email"
        );
    }

    private String getEmail(String provider, OAuth2User oAuth2User) {
        return switch (provider) {
            case "github" -> oAuth2User.getAttribute("email") != null 
                    ? oAuth2User.getAttribute("email") 
                    : oAuth2User.getAttribute("login") + "@github.com";
            case "facebook" -> oAuth2User.getAttribute("email");
            default -> oAuth2User.getAttribute("email");
        };
    }

    private String getName(String provider, OAuth2User oAuth2User) {
        return switch (provider) {
            case "github" -> oAuth2User.getAttribute("name") != null 
                    ? oAuth2User.getAttribute("name") 
                    : oAuth2User.getAttribute("login");
            case "facebook" -> oAuth2User.getAttribute("name");
            default -> oAuth2User.getAttribute("name");
        };
    }

    private String getAvatar(String provider, OAuth2User oAuth2User) {
        return switch (provider) {
            case "github" -> oAuth2User.getAttribute("avatar_url");
            case "facebook" -> {
                Map<String, Object> picture = oAuth2User.getAttribute("picture");
                if (picture != null) {
                    Object dataObj = picture.get("data");
                    if (dataObj instanceof Map<?, ?> dataMap) {
                        Object urlObj = dataMap.get("url");
                        yield urlObj != null ? urlObj.toString() : null;
                    }
                }
                yield null;
            }
            default -> oAuth2User.getAttribute("picture");
        };
    }

    private User createNewUser(String provider, String email, String name) {
        String[] nameParts = parseName(name);
        
        return User.builder()
                .email(email)
                .username(generateUsername(email, provider))
                .firstName(nameParts[0])
                .lastName(nameParts[1])
                .password("$oauth2$")
                .role(Role.USER)
                .isActive(true)
                .isLocked(false)
                .lastPasswordChange(java.time.LocalDateTime.now())
                .build();
    }

    private void updateExistingUser(User user, String provider, String name, String avatar) {
        if (name != null && (user.getFirstName() == null || user.getLastName() == null)) {
            String[] nameParts = parseName(name);
            if (user.getFirstName() == null) {
                user.setFirstName(nameParts[0]);
            }
            if (user.getLastName() == null) {
                user.setLastName(nameParts[1]);
            }
        }
        
        if (avatar != null && user.getAvatar() == null) {
            user.setAvatar(avatar);
        }
    }

    private String[] parseName(String name) {
        if (name != null && name.contains(" ")) {
            return name.split(" ", 2);
        }
        return new String[]{name != null ? name : "User", ""};
    }

    private String generateUsername(String email, String provider) {
        String baseUsername = email.split("@")[0];
        String sanitized = baseUsername.replaceAll("[^a-zA-Z0-9_]", "_");
        return sanitized + "_" + provider.substring(0, Math.min(3, provider.length()));
    }
}
