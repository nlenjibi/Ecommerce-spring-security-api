package com.smart_ecomernce_api.smart_ecomernce_api.security;

import com.smart_ecomernce_api.smart_ecomernce_api.modules.user.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token.expiration:3600000}")
    private Long accessTokenExpiration;

    @Value("${jwt.refresh-token.expiration:604800000}")
    private Long refreshTokenExpiration;

    /**
     * Get signing key from secret
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generate access token for user
     */
    public String generateAccessToken(User user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("username", user.getUsername())
                .claim("role", user.getRole().name())
                .claim("passwordChangedAt", user.getLastPasswordChange() != null 
                    ? user.getLastPasswordChange().atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli() 
                    : null)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Generate refresh token for user
     */
    public String generateRefreshToken(User user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenExpiration);

        return Jwts.builder()
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Get user ID from JWT token
     */
    public Long getUserIdFromToken(String token) {
        Claims claims = getClaims(token);
        return Long.parseLong(claims.getSubject());
    }

    /**
     * Get username from JWT token
     */
    public String getUsernameFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("username", String.class);
    }

    /**
     * Get email from JWT token
     */
    public String getEmailFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("email", String.class);
    }

    /**
     * Get role from JWT token
     */
    public String getRoleFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("role", String.class);
    }

    public Long getPasswordChangedAtFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("passwordChangedAt", Long.class);
    }

    public Long getUserTokenVersionFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("userTokenVersion", Long.class);
    }

    public Long getIssuedAtEpochMilli(String token) {
        Claims claims = getClaims(token);
        return claims.getIssuedAt().getTime();
    }

    /**
     * Get claims from token
     */
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Validate JWT token
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (SignatureException ex) {
            log.error("Invalid JWT signature: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty: {}", ex.getMessage());
        }
        return false;
    }

    /**
     * Get expiration date from token
     */
    public Date getExpirationDateFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getExpiration();
    }

    /**
     * Get issued at date from token
     */
    public Date getIssuedAtDateFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getIssuedAt();
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (Exception e) {
            log.error("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Get remaining time until token expires (in milliseconds)
     */
    public long getTokenRemainingTime(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            return expiration.getTime() - new Date().getTime();
        } catch (Exception e) {
            log.error("Error getting token remaining time: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * Check if token can be refreshed (not expired for more than X time)
     */
    public boolean canTokenBeRefreshed(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get access token expiration in seconds
     */
    public Long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration / 1000;
    }

    /**
     * Get refresh token expiration in seconds
     */
    public Long getRefreshTokenExpirationInSeconds() {
        return refreshTokenExpiration / 1000;
    }
}
