/**
 * -----------------------------------------------------------------------------
 * File: SecurityConfig.java
 * Project: OWASP API Vulnerable Lab - Secure Version
 * -----------------------------------------------------------------------------
 * Description:
 * This configuration class defines the Spring Security setup for the API.
 * In this secure version, password handling is improved by introducing the
 * BCryptPasswordEncoder bean to ensure all user passwords are stored and
 * compared securely using strong one-way hashing.
 *
 * Key Security Fixes Implemented:
 * 1. Added a @Bean method for BCryptPasswordEncoder (strength = 12) for secure password hashing.
 * 2. Ensured this encoder is available across the application (e.g., during signup, login, seeding).
 * 3. Retained stateless JWT-based authentication while fixing password security flaws.
 * 4. Prevented plaintext password storage or comparison anywhere in the system.
 *
 * This fix addresses the OWASP Top 10 vulnerability:
 * → A3:2017 - Sensitive Data Exposure (now categorized under A2:2021 - Cryptographic Failures)
 *
 * -----------------------------------------------------------------------------
 * Authors: Abubakkar Sharif, Umar Zeb (Student - Secure Coding Assignment)
 * Date: October 2025
 * -----------------------------------------------------------------------------
 */

package edu.nu.owaspapivulnlab.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Value;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import edu.nu.owaspapivulnlab.util.LoggingUtils;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    /**
     * Defines the SecurityFilterChain bean and registers the RateLimitFilter so that
     * rate limiting occurs BEFORE authentication (protecting unauthenticated endpoints
     * such as login/signup from brute-force).
     *
     * Note: RateLimitFilter is injected by Spring as a bean (component).
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, RateLimitFilter rateLimitFilter) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                // allow auth endpoints & h2-console (dev) publicly
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                // admin endpoints require ADMIN role
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // everything else under /api/ requires authentication
                .requestMatchers("/api/**").authenticated()
                // non-API endpoints (static content, swagger) can be permitted here as needed
                .anyRequest().permitAll()
        );

        // allow frames for H2 console (dev only)
        http.headers(h -> h.frameOptions(f -> f.disable()));

        // TASK 5 (Rate Limiting): register RateLimitFilter BEFORE authentication filters
        // This protects unauthenticated endpoints (login/signup) from brute-force attacks.
        http.addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class);

        // register JWT filter to set Authentication from token
        http.addFilterBefore(new JwtFilter(secret),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * JwtFilter handles incoming JWT tokens and populates the security context.
     * Note: JWT validation can be further improved (issuer, audience, expiry checks)
     * in future tasks related to token hardening.
     *
     * TASK 6 note: logs invalid token presentations with masked token values (so raw JWTs
     * are never written to logs).
     */
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);

        JwtFilter(String secret) { this.secret = secret; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            String token = null;
            if (auth != null && auth.startsWith("Bearer ")) {
                token = auth.substring(7);
                try {
                    Claims c = Jwts.parserBuilder().setSigningKey(secret.getBytes()).build()
                            .parseClaimsJws(token).getBody();
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    UsernamePasswordAuthenticationToken authn =
                            new UsernamePasswordAuthenticationToken(user, null,
                                    role != null
                                            ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                                            : Collections.emptyList());
                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    // Token validation failed - log a masked token and client IP for auditing,
                    // but do not reveal token contents or stack traces to clients.
                    log.warn("Invalid JWT presented from IP={} token={}", request.getRemoteAddr(), LoggingUtils.maskToken(token));
                    // continue without setting authentication (user remains unauthenticated)
                }
            }
            chain.doFilter(request, response);
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
