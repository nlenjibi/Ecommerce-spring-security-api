package com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.controller;

import com.smart_ecomernce_api.smart_ecomernce_api.common.response.ApiResponse;
import com.smart_ecomernce_api.smart_ecomernce_api.security.SecurityEventService;
import com.smart_ecomernce_api.smart_ecomernce_api.security.TokenBlacklistService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("v1/auth/security")
@Tag(name = "Security Stats", description = "Security monitoring and statistics (Admin only)")
@RequiredArgsConstructor
@Slf4j
// Class-level guard: every endpoint here requires ADMIN role.
// This is defense-in-depth — never rely solely on endpoint obscurity.
@PreAuthorize("hasRole('ADMIN')")
public class SecurityStatsController {

    private final TokenBlacklistService tokenBlacklistService;
    private final SecurityEventService securityEventService;

    @GetMapping("/stats")
    @Operation(summary = "Get security statistics",
            description = "Retrieve token blacklist and security event statistics (Admin only)",
            security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSecurityStats() {
        log.info("Security stats requested by admin");

        var blacklistStats = tokenBlacklistService.getStats();
        var securityStats  = securityEventService.getStats();

        Map<String, Object> stats = Map.of(
                "tokenBlacklist", Map.of(
                        "currentSize",      blacklistStats.currentSize(),
                        "hitRate",          formatPercent(blacklistStats.hitRate()),
                        "missRate",         formatPercent(blacklistStats.missRate()),
                        "expiryCacheSize",  blacklistStats.expiryCacheSize()
                ),
                "securityEvents", Map.of(
                        "failedAttemptsCount",   securityStats.currentFailedAttemptsCount(),
                        "hitRate",               formatPercent(securityStats.hitRate()),
                        "accessLogSize",         securityStats.accessLogSize(),
                        "maxFailedAttempts",     securityStats.maxFailedAttempts(),
                        "lockoutDurationMinutes", securityStats.lockoutDurationMinutes()
                )
        );

        return ResponseEntity.ok(ApiResponse.success("Security stats retrieved", stats));
    }

    /**
     * Manual cleanup trigger for ops use.
     * Prefer the scheduled job (AuthMaintenanceScheduler) under normal operation.
     */
    @PostMapping("/cleanup")
    @Operation(summary = "Trigger manual cleanup",
            description = "Manually expire blacklisted tokens and security event records (Admin only)",
            security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiResponse<String>> triggerCleanup() {
        log.info("Manual security cleanup triggered by admin");
        tokenBlacklistService.clearExpiredTokens();
        securityEventService.clearExpiredAttempts();
        return ResponseEntity.ok(ApiResponse.success("Cleanup completed", "Expired entries removed"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String formatPercent(double rate) {
        return String.format("%.2f%%", rate * 100);
    }
}