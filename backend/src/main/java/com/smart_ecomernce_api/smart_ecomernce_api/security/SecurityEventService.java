package com.smart_ecomernce_api.smart_ecomernce_api.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class SecurityEventService {

    private final Cache<String, Integer> failedLoginAttempts;
    private final Map<String, AccessLogEntry> accessLog;
    private final int maxFailedAttempts;
    private final int lockoutDurationMinutes;

    public SecurityEventService(
            @Value("${security.max-failed-attempts:5}") int maxFailedAttempts,
            @Value("${security.lockout-duration-minutes:30}") int lockoutDurationMinutes) {
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockoutDurationMinutes = lockoutDurationMinutes;
        
        this.failedLoginAttempts = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(lockoutDurationMinutes * 2, TimeUnit.MINUTES)
                .recordStats()
                .build();
        
        this.accessLog = new ConcurrentHashMap<>();
        
        log.info("SecurityEventService initialized with maxFailedAttempts={}, lockoutDurationMinutes={}", 
                maxFailedAttempts, lockoutDurationMinutes);
    }

    public void recordLoginSuccess(String identifier, String ipAddress) {
        failedLoginAttempts.invalidate(identifier.toLowerCase());
        
        log.info("LOGIN_SUCCESS: user={}, ip={}, time={}", identifier, ipAddress, LocalDateTime.now());
        
        AccessLogEntry entry = new AccessLogEntry(
                identifier,
                "LOGIN_SUCCESS",
                ipAddress,
                LocalDateTime.now(),
                "Successful login"
        );
        accessLog.put(identifier.toLowerCase(), entry);
    }

    public void recordLoginFailure(String identifier, String ipAddress, String reason) {
        String key = identifier.toLowerCase();
        int attempts = failedLoginAttempts.get(key, k -> 0) + 1;
        failedLoginAttempts.put(key, attempts);
        
        log.warn("LOGIN_FAILURE: user={}, ip={}, attempts={}, reason={}, time={}", 
                identifier, ipAddress, attempts, reason, LocalDateTime.now());
        
        boolean accountLocked = attempts >= maxFailedAttempts;
        
        AccessLogEntry entry = new AccessLogEntry(
                identifier,
                "LOGIN_FAILURE",
                ipAddress,
                LocalDateTime.now(),
                reason + (accountLocked ? " [ACCOUNT LOCKED]" : "")
        );
        accessLog.put(key, entry);
        
        if (accountLocked) {
            log.error("ACCOUNT_LOCKED: user={}, ip={}, failedAttempts={}", 
                    identifier, ipAddress, attempts);
        }
    }

    public void recordAccessDenied(String identifier, String ipAddress, String endpoint, String reason) {
        log.warn("ACCESS_DENIED: user={}, ip={}, endpoint={}, reason={}, time={}", 
                identifier, ipAddress, endpoint, reason, LocalDateTime.now());
    }

    public void recordTokenRevoked(String identifier, String reason) {
        log.info("TOKEN_REVOKED: user={}, reason={}, time={}", 
                identifier, reason, LocalDateTime.now());
    }

    public void recordOAuth2Login(String identifier, String provider, String ipAddress) {
        log.info("OAUTH2_LOGIN: user={}, provider={}, ip={}, time={}", 
                identifier, provider, ipAddress, LocalDateTime.now());
    }

    public void recordAccountLocked(String identifier, String lockedBy, String reason) {
        log.warn("ACCOUNT_LOCKED: user={}, lockedBy={}, reason={}, time={}", 
                identifier, lockedBy, reason, LocalDateTime.now());
        
        AccessLogEntry entry = new AccessLogEntry(
                identifier,
                "ACCOUNT_LOCKED",
                lockedBy,
                LocalDateTime.now(),
                reason
        );
        accessLog.put(identifier.toLowerCase(), entry);
    }

    public void recordAccountUnlocked(String identifier, String unlockedBy) {
        log.info("ACCOUNT_UNLOCKED: user={}, unlockedBy={}, time={}", 
                identifier, unlockedBy, LocalDateTime.now());
        
        AccessLogEntry entry = new AccessLogEntry(
                identifier,
                "ACCOUNT_UNLOCKED",
                unlockedBy,
                LocalDateTime.now(),
                "Account unlocked by " + unlockedBy
        );
        accessLog.put(identifier.toLowerCase(), entry);
    }

    public int getFailedLoginAttempts(String identifier) {
        return failedLoginAttempts.getIfPresent(identifier.toLowerCase()) != null 
                ? failedLoginAttempts.getIfPresent(identifier.toLowerCase()) 
                : 0;
    }

    public boolean isAccountLocked(String identifier) {
        return getFailedLoginAttempts(identifier) >= maxFailedAttempts;
    }

    public AccessLogEntry getLastAccess(String identifier) {
        return accessLog.get(identifier.toLowerCase());
    }

    public void clearExpiredAttempts() {
        failedLoginAttempts.cleanUp();
    }

    public SecurityStats getStats() {
        return new SecurityStats(
                failedLoginAttempts.estimatedSize(),
                failedLoginAttempts.stats().hitRate(),
                accessLog.size(),
                maxFailedAttempts,
                lockoutDurationMinutes
        );
    }

    public record AccessLogEntry(
            String identifier,
            String eventType,
            String ipAddress,
            LocalDateTime timestamp,
            String details
    ) {}

    public record SecurityStats(
            long currentFailedAttemptsCount,
            double hitRate,
            int accessLogSize,
            int maxFailedAttempts,
            int lockoutDurationMinutes
    ) {}
}
