package edu.nu.owaspapivulnlab.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate Limiting Filter – Task 5
 *
 * - /api/auth/login, /api/auth/signup → 5 req/min per IP
 * - /api/accounts/**               → 20 req/min per IP
 * - Returns 429 + JSON + Retry-After
 * - Fail-open on any exception
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    private Bucket createLoginBucket() {
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();   // static builder
    }

    private Bucket createAccountBucket() {
        Bandwidth limit = Bandwidth.classic(20, Refill.intervally(20, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private String getBucketKey(HttpServletRequest request) {
        String ip = getClientIp(request);
        String path = request.getRequestURI();

        if (path.startsWith("/api/auth/login") || path.startsWith("/api/auth/signup")) {
            return "auth:" + ip;
        }
        if (path.startsWith("/api/accounts")) {
            return "acct:" + ip;
        }
        return null;
    }

    private Bucket resolveBucket(String key) {
        return buckets.computeIfAbsent(key, k -> {
            if (k.startsWith("auth:")) return createLoginBucket();
            if (k.startsWith("acct:")) return createAccountBucket();
            return createLoginBucket(); // fallback
        });
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String p = request.getRequestURI();
        return p.startsWith("/h2-console") ||
               p.startsWith("/static") ||
               p.startsWith("/swagger-ui") ||
               p.startsWith("/v3/api-docs");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String key = getBucketKey(request);
        if (key != null) {
            try {
                Bucket bucket = resolveBucket(key);
                if (!bucket.tryConsume(1)) {
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setHeader("Retry-After", "60");
                    response.setContentType("application/json");
                    response.getWriter().write(
                        "{\"error\":\"too_many_requests\",\"message\":\"Rate limit exceeded. Try again in 1 minute.\"}"
                    );
                    return;
                }
            } catch (Exception e) {
                // Fail-open – never block a legitimate request because of limiter failure
            }
        }

        filterChain.doFilter(request, response);
    }
}
