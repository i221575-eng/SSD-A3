package edu.nu.owaspapivulnlab.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Global Error Handler – Tasks 6 & 8
 *
 * - Hides internal details from clients (Mass Assignment Prevention)
 * - Logs full stack traces server-side for debugging
 * - Returns consistent, minimal JSON error responses
 * - Handles validation, JWT, DB, and unexpected errors
 */
@ControllerAdvice
public class GlobalErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalErrorHandler.class);

    // ========================================================================
    // 1. Input Validation Errors (@Valid) – Task 9
    // ========================================================================
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidationErrors(MethodArgumentNotValidException ex) {
        log.debug("Validation error: {}", ex.getMessage());
        System.out.println("Validation error handler triggered!"); // Debug check

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", Instant.now().toString());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "invalid_input");
        error.put("message", "Invalid input data. Please check your request.");

        return ResponseEntity.badRequest().body(error);
    }

    // ========================================================================
    // 2. JWT / Security Exceptions – Task 7
    // ========================================================================
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<?> handleSecurity(SecurityException ex) {
        log.warn("Security violation: {}", ex.getMessage(), ex);

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", Instant.now().toString());
        error.put("status", HttpStatus.UNAUTHORIZED.value());
        error.put("error", "unauthorized");
        error.put("message", "Invalid or expired token.");

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    // ========================================================================
    // 3. Database Errors
    // ========================================================================
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> handleDatabaseError(DataAccessException ex) {
        log.error("Database error: {}", ex.getMessage(), ex);

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", Instant.now().toString());
        error.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        error.put("error", "database_error");
        error.put("message", "A database error occurred. Please try again later.");

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    // ========================================================================
    // 4. All Other Unexpected Exceptions – Fallback
    // ========================================================================
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleAll(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", Instant.now().toString());
        error.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        error.put("error", "internal_server_error");
        error.put("message", "An unexpected error occurred. Reference ID: none");

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
