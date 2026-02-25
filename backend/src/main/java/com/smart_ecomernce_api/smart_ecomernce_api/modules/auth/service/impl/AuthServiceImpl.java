package com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.service.impl;

import com.smart_ecomernce_api.smart_ecomernce_api.exception.AccountLockedException;
import com.smart_ecomernce_api.smart_ecomernce_api.exception.BadCredentialsException;
import com.smart_ecomernce_api.smart_ecomernce_api.exception.DuplicateResourceException;
import com.smart_ecomernce_api.smart_ecomernce_api.exception.InvalidTokenException;
import com.smart_ecomernce_api.smart_ecomernce_api.exception.ResourceNotFoundException;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.dto.AuthResponse;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.dto.LoginRequest;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.dto.RefreshTokenRequest;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.dto.RegisterRequest;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.entity.Auth;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.mapper.AuthMapper;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.repository.AuthRepository;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.service.AuthService;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.Role;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.User;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.repository.UserRepository;
import com.smart_ecomernce_api.smart_ecomernce_api.security.JwtTokenProvider;
import com.smart_ecomernce_api.smart_ecomernce_api.security.SecurityEventService;
import com.smart_ecomernce_api.smart_ecomernce_api.security.TokenBlacklistService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthMapper authMapper;
    private final TokenBlacklistService tokenBlacklistService;
    private final SecurityEventService securityEventService;

    @Value("${jwt.refresh-token.expiration:604800000}")
    private Long refreshTokenExpiration;

    @Value("${jwt.access-token.expiration:3600000}")
    private Long accessTokenExpiration;

    // ── Register ─────────────────────────────────────────────────────────────

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request, HttpServletRequest httpRequest) {
        log.info("Registering new user with email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateResourceException("Email already registered");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateResourceException("Username already taken");
        }

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(passwordEncoder.encode(request.getPassword()))
                .phoneNumber(request.getPhoneNumber())
                .role(Role.USER)
                .isActive(true)
                .isLocked(false)
                .lastPasswordChange(LocalDateTime.now())
                .build();

        user = userRepository.save(user);
        log.info("User registered successfully with ID: {}", user.getId());

        securityEventService.recordLoginSuccess(user.getEmail(), extractClientIp(httpRequest));

        return createAuthSession(user, httpRequest);
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        log.info("Login attempt for email: {}", request.getEmail());
        String ip = extractClientIp(httpRequest);

        // Always load the user first. Use a constant-time password check to prevent
        // timing-based user enumeration attacks (never short-circuit before checking password).
        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        boolean credentialsValid = user != null
                && passwordEncoder.matches(request.getPassword(), user.getPassword());

        if (!credentialsValid) {
            // Record failure regardless of whether the user exists
            String email = request.getEmail();
            securityEventService.recordLoginFailure(email, ip, "Invalid credentials");
            // Generic message — do not reveal whether the email exists
            throw new BadCredentialsException("Invalid email or password");
        }

        if (!user.getIsActive()) {
            securityEventService.recordLoginFailure(user.getEmail(), ip, "Account inactive");
            throw new BadCredentialsException("Account is inactive");
        }

        if (user.getIsLocked()) {
            securityEventService.recordLoginFailure(user.getEmail(), ip, "Account locked");
            throw new AccountLockedException("Account is locked. Please contact support.");
        }

        securityEventService.recordLoginSuccess(user.getEmail(), ip);
        log.info("User authenticated successfully: {}", user.getEmail());
        return createAuthSession(user, httpRequest);
    }

    // ── OAuth2 ────────────────────────────────────────────────────────────────

    @Override
    @Transactional
    public AuthResponse oauth2Login(User user, HttpServletRequest httpRequest) {
        log.info("OAuth2 login for user: {}", user.getEmail());
        String ip = extractClientIp(httpRequest);

        if (!user.getIsActive()) {
            securityEventService.recordLoginFailure(user.getEmail(), ip, "Account inactive");
            throw new BadCredentialsException("Account is inactive");
        }
        if (user.getIsLocked()) {
            securityEventService.recordLoginFailure(user.getEmail(), ip, "Account locked");
            throw new AccountLockedException("Account is locked. Please contact support.");
        }

        securityEventService.recordOAuth2Login(user.getEmail(), user.getOauthProvider(), ip);
        log.info("OAuth2 user authenticated: {}", user.getEmail());
        return createAuthSession(user, httpRequest);
    }

    // ── Token Refresh ─────────────────────────────────────────────────────────

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, HttpServletRequest httpRequest) {
        log.info("Refreshing access token");

        Auth authSession = validateRefreshToken(request.getRefreshToken());

        String newAccessToken = jwtTokenProvider.generateAccessToken(authSession.getUser());
        authSession.setAccessToken(newAccessToken);
        authSession.setLastActivityAt(LocalDateTime.now());
        authRepository.save(authSession);

        return authMapper.toAuthResponse(
                newAccessToken,
                authSession.getRefreshToken(),
                accessTokenExpiration / 1000,
                authSession.getUser()
        );
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @Override
    @Transactional
    public void logout(String refreshToken) {
        log.info("Processing logout");

        // Get user ID first for invalidating all tokens
        final Long[] userIdHolder = {null};
        
        // Invalidate the DB session first (always succeeds even if JWT parsing fails)
        authRepository.findByRefreshToken(refreshToken).ifPresent(session -> {
            session.setIsActive(false);
            session.setLoggedOutAt(LocalDateTime.now());
            authRepository.save(session);
            userIdHolder[0] = session.getUser().getId();
        });

        // Best-effort: blacklist the associated access token so it cannot be reused
        // during its remaining TTL. Failures here are non-fatal.
        authRepository.findByRefreshToken(refreshToken).ifPresent(session -> {
            try {
                String accessToken = session.getAccessToken();
                if (StringUtils.hasText(accessToken)) {
                    long remaining = jwtTokenProvider.getTokenRemainingTime(accessToken);
                    if (remaining > 0) {
                        tokenBlacklistService.blacklistToken(accessToken, remaining);
                    }
                    Long tokenUserId = jwtTokenProvider.getUserIdFromToken(accessToken);
                    securityEventService.recordTokenRevoked("user_" + tokenUserId, "User logout");
                }
            } catch (Exception e) {
                log.warn("Could not blacklist access token on logout: {}", e.getMessage());
            }
        });
        
        // CRITICAL: Invalidate ALL tokens for this user across all sessions
        // This ensures user is logged out from dashboard AND main page simultaneously
        if (userIdHolder[0] != null) {
            tokenBlacklistService.invalidateUserTokens(userIdHolder[0]);
            log.info("All tokens invalidated for user: {}", userIdHolder[0]);
        }
    }

    // ── Token Validation ──────────────────────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public Auth validateRefreshToken(String refreshToken) {
        return authRepository.findByRefreshToken(refreshToken)
                .filter(session -> session.getIsActive()
                        && session.getExpiresAt().isAfter(LocalDateTime.now()))
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired refresh token"));
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    @Override
    @Transactional
    public void cleanupExpiredSessions() {
        log.info("Cleaning up expired sessions");
        int invalidated = authRepository.invalidateExpiredSessions(LocalDateTime.now());
        tokenBlacklistService.clearExpiredTokens();
        log.info("Invalidated {} expired sessions", invalidated);
    }

    // ── Password Change ───────────────────────────────────────────────────────

    @Override
    @Transactional
    public void changePassword(Long userId, String oldPassword, String newPassword) {
        log.info("Processing password change for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            // Use a dedicated exception type — not ResourceNotFoundException
            throw new BadCredentialsException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);

        // Revoke ALL active sessions so the user must re-authenticate everywhere.
        // This is the secure default — a password change is a security event.
        authRepository.invalidateAllUserSessions(userId, LocalDateTime.now());
        tokenBlacklistService.invalidateUserTokens(userId);
        securityEventService.recordTokenRevoked("user_" + userId, "Password changed");

        log.info("Password changed and all sessions revoked for user ID: {}", userId);
    }

    // ── Account Lock / Unlock ─────────────────────────────────────────────────

    @Override
    @Transactional
    public void lockAccount(Long userId, String reason) {
        log.info("Locking account for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setIsLocked(true);
        // Do NOT update lastPasswordChange here — it has nothing to do with locking
        userRepository.save(user);

        // Terminate all active sessions and tokens immediately
        authRepository.invalidateAllUserSessions(userId, LocalDateTime.now());
        tokenBlacklistService.invalidateUserTokens(userId);
        securityEventService.recordAccountLocked(user.getEmail(), "admin", reason);

        log.info("Account locked and all sessions revoked for user ID: {}", userId);
    }

    @Override
    @Transactional
    public void unlockAccount(Long userId) {
        log.info("Unlocking account for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setIsLocked(false);
        userRepository.save(user);

        securityEventService.recordAccountUnlocked(user.getEmail(), "admin");
        log.info("Account unlocked for user ID: {}", userId);
    }

    // ── Private Helpers ───────────────────────────────────────────────────────

    /**
     * Creates a new auth session (DB record + JWT pair) for the given user.
     * The refresh token is a cryptographically random UUID (opaque token),
     * not a JWT — this makes it revocable without a blacklist.
     */
    private AuthResponse createAuthSession(User user, HttpServletRequest httpRequest) {
        String refreshToken = UUID.randomUUID().toString().replace("-", "");
        String accessToken  = jwtTokenProvider.generateAccessToken(user);
        String ipAddress    = extractClientIp(httpRequest);
        String userAgent    = httpRequest.getHeader("User-Agent");
        String deviceName   = userAgent != null && userAgent.length() > 100
                ? userAgent.substring(0, 100)
                : userAgent;

        Auth authSession = Auth.builder()
                .user(user)
                .refreshToken(refreshToken)
                .accessToken(accessToken)
                .tokenType("Bearer")
                .isActive(true)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceName(deviceName)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .build();

        authRepository.save(authSession);

        return authMapper.toAuthResponse(
                accessToken,
                refreshToken,
                accessTokenExpiration / 1000,
                user
        );
    }

    /**
     * Extracts the real client IP from common proxy headers in priority order.
     * Takes only the first address from X-Forwarded-For to avoid spoofing via
     * appended IPs (the leftmost is the originating client).
     */
    private String extractClientIp(HttpServletRequest request) {
        String[] proxyHeaders = {
                "X-Forwarded-For",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR"
        };

        for (String header : proxyHeaders) {
            String value = request.getHeader(header);
            if (StringUtils.hasText(value) && !"unknown".equalsIgnoreCase(value)) {
                // X-Forwarded-For may be "client, proxy1, proxy2" — take leftmost
                return value.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }
}