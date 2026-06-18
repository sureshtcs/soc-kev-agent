package com.deloitte.cyber.security;

import com.deloitte.cyber.dto.VulnerabilityDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Output sanitization and response filtering.
 * 
 * Prevents hallucination by:
 * 1. Removing confidently wrong answers
 * 2. Filtering out incomplete/null data
 * 3. Masking sensitive output
 * 4. Validating data consistency
 * 5. Detecting anomalies
 * 6. Removing speculative language
 */
@Component
public class OutputSanitizer {

    private static final Logger logger = LoggerFactory.getLogger(OutputSanitizer.class);

    // Patterns that indicate hallucination or confidence without grounding
    private static final Set<String> HALLUCINATION_PHRASES = new HashSet<>(Arrays.asList(
            "probably", "likely", "might be", "could be", "possibly",
            "seems like", "appears to", "may contain", "roughly", "approximately",
            "about", "estimate", "guess", "assume", "believe", "think",
            "supposedly", "allegedly", "rumor", "claim", "unconfirmed",
            "allegedly contains", "possibly affected", "suspected"
    ));

    // Sensitive fields that should be redacted from output
    private static final Set<String> SENSITIVE_FIELDS = new HashSet<>(Arrays.asList(
            "password", "api_key", "secret", "token", "credential",
            "private_key", "access_token", "refresh_token", "auth_code",
            "aws_secret", "database_url", "connection_string"
    ));

    /**
     * Validate and sanitize a single vulnerability DTO before returning.
     * Rejects entries with missing critical fields.
     */
    public ValidationResult validateVulnerability(VulnerabilityDTO vuln) {
        ValidationResult result = new ValidationResult();

        // Critical fields that must exist
        if (vuln.getCveID() == null || vuln.getCveID().trim().isEmpty()) {
            result.addIssue("CVE ID is missing or empty");
        }

        if (vuln.getVendorProject() == null || vuln.getVendorProject().trim().isEmpty()) {
            result.addIssue("Vendor is missing or empty");
        }

        if (vuln.getProduct() == null || vuln.getProduct().trim().isEmpty()) {
            result.addIssue("Product is missing or empty");
        }

        if (vuln.getDateAdded() == null) {
            result.addIssue("Date added is missing");
        }

        // Soft fields - warn but don't fail
        if (vuln.getShortDescription() == null || vuln.getShortDescription().trim().isEmpty()) {
            logger.warn("Description missing for {}", vuln.getCveID());
        }

        if (vuln.getDueDate() == null) {
            logger.warn("Due date missing for {}", vuln.getCveID());
        }

        // CVE ID format validation
        if (vuln.getCveID() != null && !vuln.getCveID().matches("CVE-\\d{4}-\\d{4,}")) {
            result.addIssue("CVE ID format invalid: " + vuln.getCveID());
        }

        // Detect anomalies (data consistency checks)
        if (vuln.getDueDate() != null && vuln.getDateAdded() != null) {
            if (vuln.getDueDate().isBefore(vuln.getDateAdded())) {
                result.addIssue("Due date is before date added (data inconsistency)");
            }
        }

        // Check for suspiciously long descriptions (possible injection)
        if (vuln.getShortDescription() != null && vuln.getShortDescription().length() > 2000) {
            result.addIssue("Description suspiciously long (possible injection attempt)");
        }

        result.setValid(result.getIssues().isEmpty());
        return result;
    }

    /**
     * Filter vulnerabilities to remove hallucinated/incomplete entries.
     * Returns only high-confidence, complete entries.
     */
    public List<VulnerabilityDTO> filterHallucinatedResults(List<VulnerabilityDTO> results) {
        List<VulnerabilityDTO> filtered = new ArrayList<>();

        for (VulnerabilityDTO vuln : results) {
            ValidationResult validation = validateVulnerability(vuln);
            
            if (validation.isValid()) {
                filtered.add(vuln);
            } else {
                logger.warn("Filtered out hallucinated/invalid entry: {} - Issues: {}", 
                    vuln.getCveID(), validation.getIssues());
            }
        }

        return filtered;
    }

    /**
     * Sanitize a response answer string.
     * Removes speculative language that indicates hallucination.
     */
    public String sanitizeAnswerText(String answer) {
        if (answer == null || answer.isEmpty()) {
            return answer;
        }

        String sanitized = answer;

        // Remove common hallucination indicators
        for (String phrase : HALLUCINATION_PHRASES) {
            // Case-insensitive replacement with word boundaries
            sanitized = sanitized.replaceAll("(?i)\\b" + Pattern.quote(phrase) + "\\b", "");
        }

        // Remove multiple spaces
        sanitized = sanitized.replaceAll("\\s+", " ").trim();

        // Remove sentences that end with question marks (uncertainty)
        sanitized = sanitized.replaceAll("[^.!]*\\?\\s*", "");

        // If answer became empty after sanitization, flag it
        if (sanitized.isEmpty()) {
            logger.warn("Answer completely sanitized - was pure speculation");
            return "[Insufficient data to answer with confidence]";
        }

        return sanitized;
    }

    /**
     * Redact sensitive data from output that might have leaked.
     */
    public String redactSensitiveData(String text) {
        if (text == null) return text;

        // Redact email addresses
        text = text.replaceAll(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
            "[REDACTED_EMAIL]");

        // Redact IP addresses
        text = text.replaceAll(
            "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b",
            "[REDACTED_IP]");

        // Redact SSN
        text = text.replaceAll(
            "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            "[REDACTED_SSN]");

        // Redact credit card
        text = text.replaceAll(
            "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b",
            "[REDACTED_CC]");

        // Redact API keys / tokens
        text = text.replaceAll(
            "(?i)(api[_-]?key|token|secret|password)\\s*[:=]\\s*[^\\s]+",
            "[REDACTED_CREDENTIAL]");

        return text;
    }

    /**
     * Check if a finding looks hallucinated (has red flags).
     */
    public HallucinationCheck checkForHallucination(VulnerabilityDTO vuln) {
        HallucinationCheck check = new HallucinationCheck();

        // Flag 1: Missing critical fields
        if (vuln.getCveID() == null || vuln.getVendorProject() == null) {
            check.addRedFlag("Missing critical fields (CVE or Vendor)");
        }

        // Flag 2: Suspiciously generic descriptions
        if (vuln.getShortDescription() != null) {
            String desc = vuln.getShortDescription().toLowerCase();
            if (desc.length() < 10) {
                check.addRedFlag("Description too vague (< 10 chars)");
            }
            if (desc.contains("unknown") || desc.contains("unspecified") || desc.contains("generic")) {
                check.addRedFlag("Description is generic/vague");
            }
        }

        // Flag 3: Impossible CVSS scores
        if (vuln.getCvssScore() != null) {
            if (vuln.getCvssScore() < 0 || vuln.getCvssScore() > 10) {
                check.addRedFlag("CVSS score out of valid range (0-10)");
            }
        }

        // Flag 4: Suspicious vendor names (e.g., "unknown vendor")
        if (vuln.getVendorProject() != null) {
            String vendor = vuln.getVendorProject().toLowerCase();
            if (vendor.contains("unknown") || vendor.contains("generic") || 
                vendor.contains("unidentified") || vendor.length() > 100) {
                check.addRedFlag("Vendor name suspicious or too long");
            }
        }

        // Flag 5: Date inconsistency
        if (vuln.getDateAdded() != null && vuln.getDueDate() != null) {
            if (vuln.getDueDate().isBefore(vuln.getDateAdded())) {
                check.addRedFlag("Due date before date added (temporal anomaly)");
            }
        }

        // Flag 6: Null dates when we expect them
        if (vuln.getDateAdded() == null) {
            check.addRedFlag("Date added is null");
        }

        check.setConfidentlyWrong(check.getRedFlags().size() >= 2);
        return check;
    }

    /**
     * Generate confidence assessment based on data quality.
     */
    public ConfidenceAssessment assessConfidence(List<VulnerabilityDTO> results) {
        ConfidenceAssessment assessment = new ConfidenceAssessment();

        if (results == null || results.isEmpty()) {
            assessment.setLevel("LOW");
            assessment.setReason("No results found");
            return assessment;
        }

        int totalResults = results.size();
        int validResults = 0;
        int flaggedResults = 0;

        for (VulnerabilityDTO result : results) {
            ValidationResult validation = validateVulnerability(result);
            if (validation.isValid()) {
                validResults++;
            }

            HallucinationCheck hallCheck = checkForHallucination(result);
            if (hallCheck.isConfidentlyWrong()) {
                flaggedResults++;
            }
        }

        double validityRatio = (double) validResults / totalResults;
        double hallucRatio = (double) flaggedResults / totalResults;

        if (hallucRatio > 0.5) {
            assessment.setLevel("VERY_LOW");
            assessment.setReason(String.format("%.0f%% of results flagged as hallucinated", hallucRatio * 100));
        } else if (validityRatio < 0.7) {
            assessment.setLevel("LOW");
            assessment.setReason(String.format("Only %.0f%% of results valid", validityRatio * 100));
        } else if (validityRatio < 0.9) {
            assessment.setLevel("MEDIUM");
            assessment.setReason(String.format("%.0f%% valid, some data quality issues", validityRatio * 100));
        } else {
            assessment.setLevel("HIGH");
            assessment.setReason("All results validated and grounded in source data");
        }

        assessment.setValidResultCount(validResults);
        assessment.setTotalResultCount(totalResults);
        return assessment;
    }

    /**
     * Validation result for a single vulnerability.
     */
    public static class ValidationResult {
        private boolean valid;
        private List<String> issues = new ArrayList<>();

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public List<String> getIssues() {
            return issues;
        }

        public void addIssue(String issue) {
            this.issues.add(issue);
        }
    }

    /**
     * Hallucination check result.
     */
    public static class HallucinationCheck {
        private List<String> redFlags = new ArrayList<>();
        private boolean confidentlyWrong;

        public List<String> getRedFlags() {
            return redFlags;
        }

        public void addRedFlag(String flag) {
            this.redFlags.add(flag);
        }

        public boolean isConfidentlyWrong() {
            return confidentlyWrong;
        }

        public void setConfidentlyWrong(boolean confidentlyWrong) {
            this.confidentlyWrong = confidentlyWrong;
        }
    }

    /**
     * Confidence assessment for results.
     */
    public static class ConfidenceAssessment {
        private String level; // LOW, MEDIUM, HIGH, VERY_LOW
        private String reason;
        private int validResultCount;
        private int totalResultCount;

        public String getLevel() {
            return level;
        }

        public void setLevel(String level) {
            this.level = level;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }

        public int getValidResultCount() {
            return validResultCount;
        }

        public void setValidResultCount(int validResultCount) {
            this.validResultCount = validResultCount;
        }

        public int getTotalResultCount() {
            return totalResultCount;
        }

        public void setTotalResultCount(int totalResultCount) {
            this.totalResultCount = totalResultCount;
        }
    }
}