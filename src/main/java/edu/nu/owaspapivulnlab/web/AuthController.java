package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import edu.nu.owaspapivulnlab.util.LoggingUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Auth Controller – Tasks 1, 4, 6
 *
 * - Task 1: BCrypt password hashing + secure comparison
 * - Task 4: DTOs prevent data exposure (no password/role in responses)
 * - Task 8: Secure logging (no passwords, masked tokens)
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder;
    }

    // ========================================================================
    // DTOs – Task 4: Prevent mass assignment & data exposure
    // ========================================================================
    public static class LoginReq {
        @NotBlank(message = "Username is required")
        public String username;

        @NotBlank(message = "Password is required")
        public String password;
    }

    public static class SignupReq {
        @NotBlank(message = "Username is required")
        public String username;

        @NotBlank(message = "Password is required")
        public String password;

        @Email(message = "Valid email is required")
        public String email;
    }

    public static class TokenRes {
        private final String token;
        public TokenRes(String token) { this.token = token; }
        public String getToken() { return token; }
    }

    // ========================================================================
    // Signup – Task 1: BCrypt + Task 4: DTO + Task 8: Logging
    // ========================================================================
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupReq req, HttpServletRequest servletReq) {
        String clientIp = getClientIp(servletReq);
        log.info("Signup attempt: username='{}' from IP={}", LoggingUtils.maskUsername(req.username), clientIp);

        if (users.findByUsername(req.username).isPresent()) {
            log.warn("Signup failed: username already taken='{}' from IP={}", LoggingUtils.maskUsername(req.username), clientIp);
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "username_taken"));
        }

        AppUser user = AppUser.builder()
                .username(req.username)
                .password(passwordEncoder.encode(req.password)) // BCrypt hash
                .email(req.email)
                .role("USER")
                .isAdmin(false)
                .build();

        AppUser saved = users.save(user);

        log.info("User created: id={} username='{}' from IP={}", saved.getId(), LoggingUtils.maskUsername(saved.getUsername()), clientIp);

        // Task 4: Return minimal data — NEVER return password, role, isAdmin
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "id", saved.getId(),
                "username", saved.getUsername(),
                "email", saved.getEmail()
        ));
    }

    // ========================================================================
    // Login – Task 1: BCrypt + Task 4: Token only + Task 6: Logging
    // ========================================================================
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginReq req, HttpServletRequest servletReq) {
        String clientIp = getClientIp(servletReq);
        Optional<AppUser> userOpt = users.findByUsername(req.username);

        if (userOpt.isEmpty()) {
            log.warn("Login failed (invalid username): username='{}' from IP={}", LoggingUtils.maskUsername(req.username), clientIp);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "invalid_credentials"));
        }

        AppUser user = userOpt.get();

        if (!passwordEncoder.matches(req.password, user.getPassword())) {
            log.warn("Login failed (invalid password): username='{}' from IP={}", LoggingUtils.maskUsername(req.username), clientIp);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "invalid_credentials"));
        }

        // JWT claims – server-controlled only
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole());
        claims.put("username", user.getUsername());

        String token = jwt.issue(String.valueOf(user.getId()), claims); // subject = userId

        log.info("Login successful: userId={} username='{}' from IP={} token={}",
                user.getId(), LoggingUtils.maskUsername(user.getUsername()), clientIp, LoggingUtils.maskToken(token));

        // Task 4: Return only token — no user object
        return ResponseEntity.ok(new TokenRes(token));
    }

    // ========================================================================
    // Helper: Extract client IP (handles X-Forwarded-For)
    // ========================================================================
    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
