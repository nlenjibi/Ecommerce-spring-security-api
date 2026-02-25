package com.smart_ecomernce_api.smart_ecomernce_api.security;

import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.User;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserRepository userRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                if (tokenBlacklistService.isTokenBlacklisted(jwt)) {
                    log.warn("Blacklisted token attempted: {}", jwt.substring(0, Math.min(20, jwt.length())));
                    SecurityContextHolder.clearContext();
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\": \"Token has been revoked\"}");
                    return;
                }

                Long userId = jwtTokenProvider.getUserIdFromToken(jwt);
                Long tokenPasswordChangedAt = jwtTokenProvider.getPasswordChangedAtFromToken(jwt);
                Long tokenIssuedAt = jwtTokenProvider.getIssuedAtEpochMilli(jwt);

                User user = userRepository.findById(userId).orElse(null);

                if (user != null && user.getIsLocked()) {
                    log.warn("Locked account attempted: {}", userId);
                    SecurityContextHolder.clearContext();
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\": \"Account is locked. Please contact support.\"}");
                    return;
                }

                if (tokenPasswordChangedAt != null && user != null && user.getLastPasswordChange() != null) {
                    long userPasswordChangedAt = user.getLastPasswordChange()
                            .atZone(ZoneId.systemDefault())
                            .toInstant()
                            .toEpochMilli();
                    if (tokenPasswordChangedAt < userPasswordChangedAt) {
                        log.warn("Token issued before password change for user: {}", userId);
                        SecurityContextHolder.clearContext();
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("{\"error\": \"Password has been changed. Please login again.\"}");
                        return;
                    }
                }

                Long userTokenVersion = tokenBlacklistService.getUserTokenVersion(userId);
                if (userTokenVersion != null && !tokenBlacklistService.isUserTokenVersionValid(userId, userTokenVersion)) {
                    log.warn("Token version invalid for user: {}", userId);
                    SecurityContextHolder.clearContext();
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\": \"Session invalidated. Please login again.\"}");
                    return;
                }

                UserDetails userDetails = customUserDetailsService.loadUserById(userId);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("Set authentication for user: {}", userId);
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }
}
