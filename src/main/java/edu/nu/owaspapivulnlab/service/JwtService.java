package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;   // Fixed: Jakarta EE (Spring Boot 3)
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * JWT Service – Hardened for Task 7
 *
 * Fixes:
 * - Loads strong secret from environment variables
 * - Enforces minimum 32-char secret
 * - Sets short token lifetime (configurable, default 15 min)
 * - Includes and validates issuer + audience claims
 * - Strictly validates signature, expiry, and claims
 * - Uses Jakarta EE annotations (SB3 compatible)
 *
 * Security: Never store passwords or secrets in JWT claims.
 */
@Service
public class JwtService {

    // --- Configurable via application.properties or env vars ---
    @Value("${jwt.secret:${app.jwt.secret:}}")
    private String secret;

    @Value("${jwt.ttl.seconds:${app.jwt.ttl-seconds:900}}") // 15 min default
    private long ttlSeconds;

    @Value("${jwt.issuer:${app.jwt.issuer:owasp-api-vuln-lab}}")
    private String issuer;

    @Value("${jwt.audience:${app.jwt.audience:owasp-api-clients}}")
    private String audience;

    @Value("${jwt.algorithm:HS256}")
    private String algorithmName;

    @Value("${jwt.clock.skew.seconds:60}")
    private long clockSkewSeconds;

    // --- Runtime ---
    private SecretKey signingKey;

    @PostConstruct
    private void init() {
        // Task 7: Strong secret from environment
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalStateException("JWT secret must be set via 'jwt.secret' or 'app.jwt.secret'");
        }
        if (secret.length() < 32) {
            throw new IllegalStateException("JWT secret must be at least 32 characters long for HS256");
        }

        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        // Normalize defaults
        if (issuer == null || issuer.trim().isEmpty()) this.issuer = "owasp-api-vuln-lab";
        if (audience == null || audience.trim().isEmpty()) this.audience = "owasp-api-clients";
    }

    /**
     * Issue JWT with subject (userId) and optional claims.
     */
    public String issue(String subject, Map<String, Object> claims) {
        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiry = Date.from(now.plusSeconds(ttlSeconds)); // Short TTL

        SignatureAlgorithm alg = parseAlgorithm(algorithmName);

        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims != null ? claims : Map.of())
                .setIssuer(issuer)           // Issuer claim
                .setAudience(audience)       // Audience claim
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(signingKey, alg)
                .compact();
    }

    /**
     * Parse and strictly validate JWT.
     * Throws SecurityException on any failure.
     */
    public Jws<Claims> parseAndValidate(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .requireIssuer(issuer)           // Validate issuer
                    .requireAudience(audience)       // Validate audience
                    .setAllowedClockSkewSeconds(clockSkewSeconds)
                    .build()
                    .parseClaimsJws(token);          // Validates signature + expiry
        } catch (JwtException e) {
            throw new SecurityException("Invalid JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Parse claims (throws JwtException on error).
     */
    public Claims parseClaims(String token) {
        return parseAndValidate(token).getBody();
    }

    /**
     * Extract subject (userId) from valid token.
     */
    public String getSubject(String token) {
        return parseAndValidate(token).getBody().getSubject();
    }

    /**
     * Safely map algorithm string to enum.
     */
    private SignatureAlgorithm parseAlgorithm(String name) {
        if (name == null) return SignatureAlgorithm.HS256;
        try {
            return SignatureAlgorithm.valueOf(name);
        } catch (IllegalArgumentException e) {
            return SignatureAlgorithm.HS256;
        }
    }
}
