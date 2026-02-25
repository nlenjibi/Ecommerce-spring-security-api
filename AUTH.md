# Authentication & Security Documentation

This document explains the authentication and security implementation in the Smart E-Commerce System.

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Security Components](#security-components)
- [Authentication Flow](#authentication-flow)
- [JWT Implementation](#jwt-implementation)
- [OAuth2 Integration](#oauth2-integration)
- [Role-Based Access Control](#role-based-access-control)
- [CORS Configuration](#cors-configuration)
- [CSRF Protection](#csrf-protection)
- [Security Services](#security-services)
- [API Endpoints](#api-endpoints)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐              │
│  │   Client     │────▶│  Security    │────▶│   Auth      │              │
│  │  (React/     │     │   Filter     │     │   Service    │              │
│  │   Vue/Ang)   │     │   Chain      │     │              │              │
│  └──────────────┘     └──────────────┘     └──────────────┘              │
│         │                     │                     │                     │
│         │                     │                     │                     │
│         ▼                     ▼                     ▼                     │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐              │
│  │   JWT/       │     │  JwtToken    │     │    User      │              │
│  │   OAuth2     │     │  Provider    │     │  Repository  │              │
│  │   Token      │     │              │     │              │              │
│  └──────────────┘     └──────────────┘     └──────────────┘              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Components

### 1. SecurityConfig.java
**Location:** `config/SecurityConfig.java`

Main Spring Security configuration that orchestrates all security components.

**Key Responsibilities:**
- Configures HTTP security (CSRF, CORS, Session management)
- Defines authorization rules for endpoints
- Sets up OAuth2 login with Google, GitHub, Facebook
- Integrates JWT authentication filter
- Configures password encoding with BCrypt

**Configuration Details:**
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    // JWT Authentication Filter
    // OAuth2 Login Configuration
    // CORS Configuration
    // Authorization Rules
}
```

**Key Features:**
- Stateless session management (JWT-based)
- Custom authentication entry point
- Method-level security with `@PreAuthorize`
- BCrypt password encoding

---

### 2. JwtTokenProvider.java
**Location:** `modules/auth/security/JwtTokenProvider.java`

Handles JWT token generation, validation, and parsing.

**Key Methods:**
```java
public class JwtTokenProvider {
    // Generate access token with user claims
    public String generateAccessToken(User user)
    
    // Generate refresh token
    public String generateRefreshToken(User user)
    
    // Extract user ID from token
    public Long getUserIdFromToken(String token)
    
    // Extract role from token
    public String getRoleFromToken(String token)
    
    // Validate token signature and expiration
    public boolean validateToken(String token)
}
```

**Token Configuration:**
- **Algorithm:** HS512 (HMAC SHA-512)
- **Access Token Expiration:** 1 hour (configurable)
- **Refresh Token Expiration:** 7 days (configurable)
- **Claims:** userId, email, username, role

---

### 3. JwtAuthenticationFilter.java
**Location:** `modules/auth/security/JwtAuthenticationFilter.java`

Spring Security filter that intercepts requests and validates JWT tokens.

**Filter Chain Position:**
```
Request → CORS Filter → CSRF Filter → JwtAuthenticationFilter → UsernamePasswordAuthenticationFilter
```

**Responsibilities:**
1. Extract JWT from Authorization header
2. Validate token using JwtTokenProvider
3. Check token blacklist (for revoked tokens)
4. Set authentication in SecurityContext
5. Pass request to next filter

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) {
        // 1. Extract token from request
        // 2. Validate token
        // 3. Check blacklist
        // 4. Set authentication
    }
}
```

---

### 4. JwtAuthenticationEntryPoint.java
**Location:** `modules/auth/security/JwtAuthenticationEntryPoint.java`

Handles authentication failures - returns 401 Unauthorized responses.

```java
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request,
                        HttpServletResponse response,
                        AuthenticationException authException) {
        // Return 401 with error JSON
    }
}
```

---

### 5. CustomUserDetailsService.java
**Location:** `modules/auth/security/CustomUserDetailsService.java`

Loads user details from database for authentication.

**Key Methods:**
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    // Load user by email/username
    public UserDetails loadUserByUsername(String usernameOrEmail)
    
    // Load user by ID (used by JWT filter)
    public UserDetails loadUserById(Long id)
}
```

**Returns:** Spring Security `User` object with:
- Username (email)
- Password (BCrypt hashed)
- Authorities (ROLE_CUSTOMER, ROLE_ADMIN, etc.)
- Account status (enabled, locked, expired)

---

### 6. CustomOAuth2UserService.java
**Location:** `modules/auth/security/CustomOAuth2UserService.java`

Handles OAuth2 user authentication from external providers.

**Supported Providers:**
- Google
- GitHub
- Facebook

**Key Features:**
- Creates new user if not exists
- Maps OAuth2 attributes to User entity
- Generates unique username per provider
- Updates existing user info on login

```java
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        // 1. Get user info from OAuth provider
        // 2. Check if user exists in database
        // 3. Create or update user
        // 4. Return OAuth2User with custom attributes
    }
}
```

---

### 7. TokenBlacklistService.java
**Location:** `modules/auth/security/TokenBlacklistService.java`

Manages invalidated tokens for logout functionality.

**Implementation:**
- Uses Caffeine cache for in-memory storage
- Automatic expiration based on token expiry time
- Configurable maximum blacklist size

```java
@Service
public class TokenBlacklistService {
    // Add token to blacklist
    public void blacklistToken(String token, long expirationTime)
    
    // Check if token is blacklisted
    public boolean isTokenBlacklisted(String token)
    
    // Remove token from blacklist
    public void removeFromBlacklist(String token)
}
```

---

### 8. SecurityEventService.java
**Location:** `modules/auth/security/SecurityEventService.java`

Tracks security events for auditing and monitoring.

**Tracked Events:**
- Login success/failure
- Account lockout
- Token revocation
- OAuth2 login

```java
@Service
public class SecurityEventService {
    public void recordLoginSuccess(String identifier, String ipAddress)
    public void recordLoginFailure(String identifier, String ipAddress, String reason)
    public void recordTokenRevoked(String identifier, String reason)
    public void recordOAuth2Login(String identifier, String provider, String ipAddress)
}
```

---

## Authentication Flow

### Username/Password Login

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  AuthController │────▶│ AuthService │────▶│   User      │
│             │     │  /login      │     │             │     │ Repository  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Send       │     │  Validate   │     │  Check      │     │  Find user  │
│  credentials│     │  request    │     │  password   │     │  by email   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Receive    │     │  Generate   │     │  Create     │     │  Return     │
│  JWT tokens │◀────│  JWT tokens │◀────│  session    │◀────│  user       │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

**Step-by-step:**
1. Client sends POST to `/v1/auth/login` with email/password
2. AuthController validates request
3. AuthService verifies credentials against database
4. JwtTokenProvider generates access + refresh tokens
5. Auth session created in database
6. Response returned with tokens

---

### OAuth2 Login Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  Redirect   │────▶│   OAuth     │────▶│  Callback   │
│             │     │  to Google  │     │  Provider  │     │  /success   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                                                            │
       │                                                            ▼
       │                                                   ┌─────────────┐
       │                                                   │  Generate   │
       │◀──────────────────────────────────────────────────│  JWT tokens │
       │                                                   └─────────────┘
```

**Step-by-step:**
1. Client redirects to `/oauth2/authorization/google`
2. Spring Security redirects to Google OAuth
3. User grants permission
4. Google redirects to `/login/oauth2/code/google`
5. CustomOAuth2UserService loads/creates user
6. OAuth2Controller generates JWT tokens
7. Client receives tokens

---

## JWT Implementation

### Token Structure

**Access Token:**
```json
{
  "sub": "12345",
  "email": "user@example.com",
  "username": "johndoe",
  "role": "CUSTOMER",
  "iat": 1704067200,
  "exp": 1704070800
}
```

**Header:**
```json
{
  "alg": "HS512",
  "typ": "JWT"
}
```

### Token Storage

| Token Type | Storage | Expiration |
|------------|---------|------------|
| Access Token | Client (memory/localStorage) | 1 hour |
| Refresh Token | HttpOnly Cookie / Client | 7 days |
| Blacklisted Token | Caffeine Cache | Until expiry |

---

## OAuth2 Integration

### Configuration

**application-dev.yml:**
```yaml
spring.security.oauth2.client.registration.google:
  client-id: ${GOOGLE_CLIENT_ID}
  client-secret: ${GOOGLE_CLIENT_SECRET}
  scope: profile, email

spring.security.oauth2.client.registration.github:
  client-id: ${GITHUB_CLIENT_ID}
  client-secret: ${GITHUB_CLIENT_SECRET}
  scope: read:user, user:email

spring.security.oauth2.client.registration.facebook:
  client-id: ${FACEBOOK_CLIENT_ID}
  client-secret: ${FACEBOOK_CLIENT_SECRET}
  scope: email, public_profile
```

### Environment Variables

```bash
# Google
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Facebook
FACEBOOK_CLIENT_ID=your-facebook-client-id
FACEBOOK_CLIENT_SECRET=your-facebook-client-secret
```

---

## Role-Based Access Control

### Roles

| Role | Description | Access Level |
|------|-------------|--------------|
| CUSTOMER | Regular user | Own data, make orders |
| STAFF | Staff member | Limited admin access |
| ADMIN | Administrator | Full access |

### Implementation

**1. Role Enum:**
```java
public enum Role {
    CUSTOMER,
    STAFF,
    ADMIN
}
```

**2. Method-Level Security:**
```java
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/users/{id}")
public ResponseEntity<Void> deleteUser(@PathVariable Long id)

@PreAuthorize("hasAnyRole('ADMIN', 'STAFF')")
@GetMapping("/orders")
public ResponseEntity<List<Order>> getAllOrders()
```

**3. Endpoint Authorization (SecurityConfig):**
```java
.requestMatchers("/v1/auth/account/**").hasRole("ADMIN")
.anyRequest().authenticated()
```

---

## CORS Configuration

**Location:** `SecurityConfig.java`

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of(
        "http://localhost:3000",  // React
        "http://localhost:4200",  // Angular
        "http://localhost:5173"   // Vue
    ));
    configuration.setAllowedMethods(Arrays.asList(
        "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
    ));
    configuration.setAllowedHeaders(Arrays.asList("*"));
    configuration.setExposedHeaders(Arrays.asList("Authorization"));
    configuration.setAllowCredentials(true);
    
    return source;
}
```

**CORS Headers:**
- `Access-Control-Allow-Origin`: Allowed origins
- `Access-Control-Allow-Methods`: Allowed HTTP methods
- `Access-Control-Allow-Headers`: Allowed request headers
- `Access-Control-Expose-Headers`: Headers visible to client
- `Access-Control-Allow-Credentials`: Allow cookies

---

## CSRF Protection

### Configuration

**CSRF is DISABLED** for JWT-based APIs (stateless).

```java
http
    .csrf(AbstractHttpConfigurer::disable)  // Stateless API
```

### Why Disabled?

1. **Stateless Authentication:** JWT tokens are self-contained
2. **No Session:** No server-side session to hijack
3. **Bearer Tokens:** Tokens sent in Authorization header
4. **Single Page Apps:** Traditional CSRF tokens not practical

### When to Enable?

Enable CSRF for:
- Server-side rendered pages with forms
- Stateful sessions
- Traditional MVC endpoints

---

## Security Services

### AuthService

**Interface:** `modules/auth/service/AuthService.java`

**Key Methods:**
```java
public interface AuthService {
    AuthResponse register(RegisterRequest request, HttpServletRequest httpRequest);
    AuthResponse login(LoginRequest request, HttpServletRequest httpRequest);
    AuthResponse refreshToken(RefreshTokenRequest request, HttpServletRequest httpRequest);
    void logout(String refreshToken);
    void changePassword(Long userId, String oldPassword, String newPassword);
    void lockAccount(Long userId, String reason);
    void unlockAccount(Long userId);
}
```

### AuthController

**Endpoints:**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/v1/auth/register` | Register new user | No |
| POST | `/v1/auth/login` | User login | No |
| POST | `/v1/auth/refresh` | Refresh access token | No |
| POST | `/v1/auth/logout` | User logout | Yes |
| POST | `/v1/auth/password/change` | Change password | Yes |
| POST | `/v1/auth/account/lock` | Lock account (admin) | Yes (ADMIN) |
| POST | `/v1/auth/account/unlock` | Unlock account (admin) | Yes (ADMIN) |

### OAuth2Controller

**Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/auth/oauth2/success` | OAuth2 callback (success) |
| GET | `/v1/auth/oauth2/failure` | OAuth2 callback (failure) |
| GET | `/v1/auth/oauth2/providers` | List available providers |

---

## API Endpoints

### Authentication Endpoints

```bash
# Register
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "firstName": "John",
  "lastName": "Doe",
  "password": "securePassword123"
}

# Login
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123"
}

# Response
{
  "accessToken": "eyJhbGciOiJIUzUxMi...",
  "refreshToken": "dGhpcyBpcyBhIHJlZnJl...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "johndoe",
    "role": "CUSTOMER"
  }
}

# Using the token
curl -H "Authorization: Bearer {accessToken}" \
  http://localhost:8080/api/v1/user/profile
```

### OAuth2 Endpoints

```bash
# Google Login
GET /api/oauth2/authorization/google

# GitHub Login  
GET /api/oauth2/authorization/github

# Facebook Login
GET /api/oauth2/authorization/facebook
```

---

## Security Best Practices Implemented

1. **Password Hashing:** BCrypt with salt
2. **Token Security:** HS512 algorithm
3. **Token Blacklisting:** Revoked tokens blocked
4. **Account Lockout:** After 5 failed attempts
5. **Audit Logging:** All auth events logged
6. **CORS:** Strict origin whitelist
7. **Stateless:** No server-side sessions
8. **Method Security:** Role-based access control

---

## Troubleshooting

### Common Issues

**1. Token Expired:**
```json
{
  "error": "Token has expired",
  "code": "TOKEN_EXPIRED"
}
```
Solution: Use refresh token to get new access token

**2. Invalid Token:**
```json
{
  "error": "Invalid JWT token",
  "code": "INVALID_TOKEN"
}
```
Solution: Re-login to get new tokens

**3. Account Locked:**
```json
{
  "error": "Account is locked",
  "code": "ACCOUNT_LOCKED"
}
```
Solution: Contact admin to unlock

**4. CORS Error:**
```
Access to fetch at 'http://localhost:8080/api/v1/auth/login' 
from origin 'http://localhost:3000' has been blocked by CORS policy
```
Solution: Add origin to allowedOrigins in SecurityConfig
