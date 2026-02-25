package com.smart_ecomernce_api.smart_ecomernce_api.config;

import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.repository.UserRepository;
import com.smart_ecomernce_api.smart_ecomernce_api.security.JwtTokenProvider;
import com.smart_ecomernce_api.smart_ecomernce_api.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.graphql.server.WebGraphQlInterceptor;
import org.springframework.graphql.server.WebGraphQlRequest;
import org.springframework.graphql.server.WebGraphQlResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Component
@RequiredArgsConstructor
@Slf4j
public class GraphQLJwtInterceptor implements WebGraphQlInterceptor {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    public @NonNull Mono<WebGraphQlResponse> intercept(@NonNull WebGraphQlRequest request, @NonNull Chain chain) {
        String authHeader = getAuthHeader(request);
        Long userId = null;

        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String token = authHeader.substring(BEARER_PREFIX.length());

            if (jwtTokenProvider.validateToken(token)) {
                try {
                    userId = jwtTokenProvider.getUserIdFromToken(token);
                    String role = jwtTokenProvider.getRoleFromToken(token);

                    userRepository.findById(userId).ifPresent(user -> {
                        UserPrincipal userPrincipal = UserPrincipal.create(user);
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        userPrincipal,
                                        null,
                                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                                );
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        log.debug("GraphQL authenticated user: {} with role: {}", user.getEmail(), role);
                    });
                } catch (Exception e) {
                    log.warn("GraphQL JWT authentication failed: {}", e.getMessage());
                }
            }
        }

        WebGraphQlRequest updatedRequest = request;
        if (userId != null) {
            final Long contextUserId = userId;
            request.configureExecutionInput((executionInput, builder) ->
                    builder.graphQLContext(context -> context.put("userId", contextUserId)).build()
            );
        }

        return chain.next(updatedRequest);
    }

    private String getAuthHeader(WebGraphQlRequest request) {
        HttpHeaders headers = request.getHeaders();
        return headers.getFirst(AUTH_HEADER);
    }
}
