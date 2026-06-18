package com.deloitte.cyber.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Input validation and sanitization for analyst queries.
 * 
 * Prevents:
 * 1. SQL injection patterns
 * 2. Malicious script injection
 * 3. Sensitive data leakage (IPs, credentials, PII)
 * 4. Command injection
 * 5. Excessive input size
 * 6. Non-ASCII/control characters
 * 7. Known bad patterns
 */
@Component
public class InputSanitizer {

    private static final Logger logger = LoggerFactory.getLogger(InputSanitizer.class);
    private static final int MAX_QUERY_LENGTH = 500;
    private static final int MIN_QUERY_LENGTH = 3;

    // SQL injection patterns
    private static final Set<String> SQL_KEYWORDS = new HashSet<>(Arrays.asList(
            "union", "select", "insert", "update", "delete", "drop", "create", "alter",
            "exec", "execute", "script", "javascript", "onclick", "onerror", "onload"
    ));

    // Sensitive data patterns
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");

    private static final Pattern CREDENTIAL_PATTERN = Pattern.compile(
            "(password|passwd|pwd|secret|api[_-]?key|token|credential)\\s*[:=]", 
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SSN_PATTERN = Pattern.compile(
            "\\b\\d{3}-\\d{2}-\\d{4}\\b");

    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
            "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b");

    // Command injection patterns
    private static final Pattern COMMAND_INJECTION = Pattern.compile(
            "[;&|`$()\\[\\]{}].*[;&|`$()\\[\\]{}]");

    // Path traversal patterns
    private static final Pattern PATH_TRAVERSAL = Pattern.compile(
            "(\\.\\./|\\.\\.\\\\|%2e%2e/|%252e%252e/)");

    /**
     * Comprehensive input validation.
     * Returns sanitization result with pass/fail and reasons.
     */
    public SanitizationResult validate(String input) {
        SanitizationResult result = new SanitizationResult();

        if (input == null) {
            result.addViolation("Input is null");
            return result;
        }

        input = input.trim();

        // 1. Length check
        if (input.length() < MIN_QUERY_LENGTH) {
            result.addViolation("Query too short (< 3 characters)");
            return result;
        }

        if (input.length() > MAX_QUERY_LENGTH) {
            result.addViolation("Query too long (> 500 characters). Please be more specific.");
            return result;
        }

        // 2. Character validation
        if (!isValidCharacterSet(input)) {
            result.addViolation("Query contains invalid characters");
            return result;
        }

        // 3. SQL injection check
        if (containsSqlInjectionPattern(input)) {
            result.addViolation("Query contains suspicious SQL patterns");
            logger.warn("Potential SQL injection attempt: {}", maskSensitive(input));
            return result;
        }

        // 4. Command injection check
        if (COMMAND_INJECTION.matcher(input).find()) {
            result.addViolation("Query contains suspicious command patterns");
            logger.warn("Potential command injection attempt: {}", maskSensitive(input));
            return result;
        }

        // 5. Path traversal check
        if (PATH_TRAVERSAL.matcher(input).find()) {
            result.addViolation("Query contains path traversal patterns");
            logger.warn("Potential path traversal attempt: {}", maskSensitive(input));
            return result;
        }

        // 6. Sensitive data detection
        if (containsSensitiveData(input)) {
            result.addViolation("Query contains sensitive data (IP, email, credentials, SSN, etc). Please remove and retry.");
            logger.warn("Sensitive data detected in query: {}", maskSensitive(input));
            return result;
        }

        // 7. Script/HTML injection
        if (containsScriptPatterns(input)) {
            result.addViolation("Query contains script/HTML patterns");
            logger.warn("Potential XSS attempt: {}", maskSensitive(input));
            return result;
        }

        result.setValid(true);
        result.setSanitizedInput(input);
        return result;
    }

    /**
     * Check for SQL injection keywords in suspicious context.
     */
    private boolean containsSqlInjectionPattern(String input) {
        String lower = input.toLowerCase();
        for (String keyword : SQL_KEYWORDS) {
            if (lower.contains(" " + keyword + " ") || 
                lower.contains(" " + keyword + ";") ||
                lower.startsWith(keyword)) {
                // Not all keywords are malicious - "select all cves" is fine
                // Only flag if multiple keywords or suspicious patterns
                int keywordCount = 0;
                for (String kw : SQL_KEYWORDS) {
                    if (lower.contains(" " + kw + " ")) {
                        keywordCount++;
                    }
                }
                if (keywordCount >= 2) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if query contains sensitive data that shouldn't be shared.
     */
    private boolean containsSensitiveData(String input) {
        return IP_PATTERN.matcher(input).find() ||
               EMAIL_PATTERN.matcher(input).find() ||
               CREDENTIAL_PATTERN.matcher(input).find() ||
               SSN_PATTERN.matcher(input).find() ||
               CREDIT_CARD_PATTERN.matcher(input).find();
    }

    /**
     * Check for script/HTML/XSS patterns.
     */
    private boolean containsScriptPatterns(String input) {
        String lower = input.toLowerCase();
        return lower.contains("<script") ||
               lower.contains("javascript:") ||
               lower.contains("onerror=") ||
               lower.contains("onload=") ||
               lower.contains("onclick=") ||
               lower.contains("eval(") ||
               lower.contains("alert(");
    }

    /**
     * Ensure input contains only printable ASCII and common special chars.
     */
    private boolean isValidCharacterSet(String input) {
        // Allow alphanumeric, spaces, and common punctuation
        // Block control characters and high Unicode
        return input.matches("[\\p{Print}\\s]*");
    }

    /**
     * Mask sensitive parts for logging.
     */
    private String maskSensitive(String input) {
        return input.replaceAll("\\d{3}-\\d{2}-(\\d{4})", "XXX-XX-$1")
                    .replaceAll("\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?(\\d{4})", "****-****-****-$1")
                    .replaceAll("([a-z0-9._%+-]+)@", "***@");
    }

    /**
     * Sanitization result object.
     */
    public static class SanitizationResult {
        private boolean valid = false;
        private String sanitizedInput;
        private String violation;

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public String getSanitizedInput() {
            return sanitizedInput;
        }

        public void setSanitizedInput(String sanitizedInput) {
            this.sanitizedInput = sanitizedInput;
        }

        public String getViolation() {
            return violation;
        }

        public void addViolation(String violation) {
            this.violation = violation;
            this.valid = false;
        }
    }
}