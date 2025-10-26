package edu.nu.owaspapivulnlab.util;

public final class LoggingUtils {

    private LoggingUtils() {}

    /**
     * Mask a password (do not log actual password).
     * Returns a constant redaction token.
     */
    public static String maskPassword(String password) {
        if (password == null) return "<null>";
        return "<REDACTED-PASSWORD>";
    }

    /**
     * Mask a JWT/token for safe logging. Keep first 6 and last 4 chars if length permits.
     * If token is short, return a short masked value.
     */
    public static String maskToken(String token) {
        if (token == null) return "<null>";
        int len = token.length();
        if (len <= 10) return "<REDACTED-TOKEN>";
        String start = token.substring(0, Math.min(6, len));
        String end = token.substring(Math.max(len - 4, 0));
        return start + "..." + end;
    }

    /**
     * Mask username for low-sensitivity logging if needed; here we return username unchanged
     * because usernames are not secret, but keep method for future policy change.
     */
    public static String maskUsername(String username) {
        if (username == null) return "<null>";
        return username;
    }
}
