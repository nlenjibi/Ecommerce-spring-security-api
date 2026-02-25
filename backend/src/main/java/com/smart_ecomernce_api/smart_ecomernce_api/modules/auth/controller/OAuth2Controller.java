package com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.controller;

import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.dto.AuthResponse;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.auth.service.AuthService;
import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.User;
import com.smart_ecomernce_api.smart_ecomernce_api.common.response.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Handles OAuth2 callbacks from Google / GitHub / Facebook.
 *
 * ── Why no cookies? ──────────────────────────────────────────────────────────
 * Cookies work well when the frontend and API share a domain. With Next.js on a
 * separate origin (e.g. Vercel) and Spring on another (e.g. Railway / EC2),
 * cross-origin cookies require SameSite=None + Secure, which is fragile and
 * browser-policy-dependent.
 *
 * ── The one-time-code pattern ────────────────────────────────────────────────
 * OAuth2 is always browser-driven (Google redirects the browser back to Spring),
 * so we can't return JSON directly. Instead:
 *
 *   1. Spring completes the OAuth2 flow and stores tokens in a short-lived
 *      in-memory map under a random one-time code (TTL = 60 s).
 *   2. Spring redirects the browser to Next.js with just the code:
 *        https://myapp.com/auth/oauth2/callback?code=<uuid>
 *   3. Next.js (server action or API route) calls POST /v1/auth/oauth2/exchange
 *      with the code and receives the full token response as JSON.
 *   4. The code is deleted immediately after exchange (truly one-time).
 *
 * The code is worthless without being exchanged, expires in 60 s, and tokens
 * never appear in browser history or logs.
 *
 * ── Production note ──────────────────────────────────────────────────────────
 * The in-memory store is fine for a single-instance deployment. If you run
 * multiple instances behind a load balancer, replace the ConcurrentHashMap
 * with a Redis key (TTL 60 s) or a short-lived DB record.
 */
@RestController
@RequestMapping("/v1/auth/oauth2")
@RequiredArgsConstructor
@Slf4j
public class OAuth2Controller {

    private final AuthService authService;

    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendUrl;

    // ── One-time code store ───────────────────────────────────────────────────

    /**
     * Short-lived store: code → AuthResponse.
     * Each entry expires after 60 seconds regardless of exchange.
     */
    private final ConcurrentHashMap<String, AuthResponse> pendingTokens = new ConcurrentHashMap<>();
    private final java.util.concurrent.ScheduledExecutorService cleaner =
            Executors.newSingleThreadScheduledExecutor();

    // ── OAuth2 Success (called by Spring Security after provider callback) ────

    @GetMapping("/success")
    public void oauth2Success(
            @AuthenticationPrincipal OAuth2User principal,
            HttpServletRequest request,
            HttpServletResponse response) throws Exception {

        if (principal == null) {
            log.warn("OAuth2 success called without principal");
            response.sendRedirect(frontendUrl + "/auth/login?error=oauth2_failed");
            return;
        }

        User user = (User) principal.getAttribute("user");
        if (user == null) {
            log.warn("OAuth2 principal has no 'user' attribute");
            response.sendRedirect(frontendUrl + "/auth/login?error=user_not_found");
            return;
        }

        String provider = (String) principal.getAttribute("provider");
        log.info("OAuth2 login successful for user: {} via {}", user.getEmail(), provider);

        // Complete the auth session (creates DB record, issues tokens)
        AuthResponse authResponse = authService.oauth2Login(user, request);

        // Generate a short-lived one-time code and store the token response
        String code = UUID.randomUUID().toString().replace("-", "");
        pendingTokens.put(code, authResponse);

        // Auto-expire after 60 seconds in case the frontend never exchanges it
        cleaner.schedule(() -> {
            pendingTokens.remove(code);
            log.debug("OAuth2 one-time code expired and removed");
        }, 60, TimeUnit.SECONDS);

        // Redirect the browser to Next.js with only the opaque code — no tokens in URL
        response.sendRedirect(frontendUrl + "/auth/oauth2/callback?code=" + code);
    }

    // ── Token Exchange (called by Next.js server-side, not the browser) ───────

    /**
     * Next.js calls this from a server action or API route (not client-side JS)
     * to exchange the one-time code for real tokens.
     *
     * Example Next.js usage (app/auth/oauth2/callback/route.ts):
     *
     *   export async function GET(req: Request) {
     *     const code = new URL(req.url).searchParams.get('code');
     *     const res  = await fetch(`${process.env.API_URL}/v1/auth/oauth2/exchange`, {
     *       method: 'POST',
     *       headers: { 'Content-Type': 'application/json' },
     *       body: JSON.stringify({ code }),
     *     });
     *     const { data } = await res.json();
     *     // Store data.accessToken and data.refreshToken in your auth context / cookie
     *   }
     */
    @PostMapping("/exchange")
    public ResponseEntity<ApiResponse<AuthResponse>> exchangeCode(
            @RequestBody Map<String, String> body) {

        String code = body.get("code");

        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Code is required"));
        }

        // Remove atomically — if null, code was already used or never existed
        AuthResponse authResponse = pendingTokens.remove(code);

        if (authResponse == null) {
            log.warn("OAuth2 code exchange failed — code not found or already used: {}", code);
            return ResponseEntity.status(401)
                    .body(ApiResponse.error("Invalid or expired code"));
        }

        log.info("OAuth2 code exchanged successfully");
        return ResponseEntity.ok(ApiResponse.success("OAuth2 login successful", authResponse));
    }

    // ── OAuth2 Failure ────────────────────────────────────────────────────────

    @GetMapping("/failure")
    public void oauth2Failure(
            @RequestParam(required = false, defaultValue = "oauth2") String provider,
            HttpServletResponse response) throws Exception {

        log.warn("OAuth2 login failed for provider: {}", provider);
        response.sendRedirect(frontendUrl + "/auth/login?error=oauth2_failed&provider=" + provider.toUpperCase());
    }

    // ── Provider Metadata (used by Next.js to build login buttons) ───────────

    @GetMapping("/providers")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getOAuth2Providers() {
        return ResponseEntity.ok(ApiResponse.success("Providers retrieved", Map.of(
                "google", Map.of(
                        "name", "Google",
                        "authUrl", "/oauth2/authorization/google",
                        "color", "#4285F4"
                ),
                "github", Map.of(
                        "name", "GitHub",
                        "authUrl", "/oauth2/authorization/github",
                        "color", "#24292e"
                ),
                "facebook", Map.of(
                        "name", "Facebook",
                        "authUrl", "/oauth2/authorization/facebook",
                        "color", "#1877F2"
                )
        )));
    }
}