package com.deloitte.cyber.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class QueryParserService {

    private static final Logger logger = LoggerFactory.getLogger(QueryParserService.class);

    public enum QueryType {
        VENDOR_EXPOSURE,
        DEADLINE,
        SEVERITY,
        RANSOMWARE,
        RECENT,
        TOP_VENDORS,
        OVERDUE,
        PATCH_PRIORITY,
        GENERIC
    }

    public ParsedQuery parseQuery(String question) {
        String lowerQuestion = question.toLowerCase();
        QueryType type = detectQueryType(lowerQuestion);
        Map<String, String> extractedData = extractKeywords(lowerQuestion);

        return new ParsedQuery(type, question, extractedData);
    }

    private QueryType detectQueryType(String lowerQuestion) {
        if (containsAny(lowerQuestion, "vendor", "product", "microsoft", "cisco", "apache", "linux", "windows", "ubuntu")) {
            if (containsAny(lowerQuestion, "how many", "count", "most")) {
                return QueryType.TOP_VENDORS;
            }
            return QueryType.VENDOR_EXPOSURE;
        }

        if (containsAny(lowerQuestion, "deadline", "due date", "patch", "remediation", "due")) {
            if (containsAny(lowerQuestion, "passed", "overdue", "expired")) {
                return QueryType.OVERDUE;
            }
            return QueryType.DEADLINE;
        }

        if (containsAny(lowerQuestion, "critical", "high", "severity", "cvss", "score")) {
            return QueryType.SEVERITY;
        }

        if (containsAny(lowerQuestion, "ransomware", "campaign")) {
            return QueryType.RANSOMWARE;
        }

        if (containsAny(lowerQuestion, "recent", "latest", "new")) {
            return QueryType.RECENT;
        }

        if (containsAny(lowerQuestion, "patch first", "patch priority", "should we patch", "what should")) {
            return QueryType.PATCH_PRIORITY;
        }

        return QueryType.GENERIC;
    }

    private Map<String, String> extractKeywords(String lowerQuestion) {
        Map<String, String> data = new HashMap<>();

        // Extract CVE ID
        if (lowerQuestion.contains("cve-")) {
            int idx = lowerQuestion.indexOf("cve-");
            data.put("cveId", lowerQuestion.substring(idx, Math.min(idx + 13, lowerQuestion.length())).toUpperCase());
        }

        // Extract vendor/product keywords
        String[] vendors = {"microsoft", "cisco", "apache", "linux", "ubuntu", "debian", "oracle", "ibm", "vmware", "adobe"};
        for (String vendor : vendors) {
            if (lowerQuestion.contains(vendor)) {
                data.put("vendor", vendor);
                break;
            }
        }

        // Extract product names
        String[] products = {"windows", "ios", "http server", "kernel", "java", "mysql", "postgresql", "nginx"};
        for (String product : products) {
            if (lowerQuestion.contains(product)) {
                data.put("product", product);
                break;
            }
        }

        // Extract number if present
        if (lowerQuestion.contains("5") || lowerQuestion.contains("10") || lowerQuestion.contains("top")) {
            data.put("limit", "5");
        }

        return data;
    }

    private boolean containsAny(String text, String... keywords) {
        for (String keyword : keywords) {
            if (text.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    public static class ParsedQuery {
        public final QueryType type;
        public final String originalQuestion;
        public final Map<String, String> extractedData;

        public ParsedQuery(QueryType type, String originalQuestion, Map<String, String> extractedData) {
            this.type = type;
            this.originalQuestion = originalQuestion;
            this.extractedData = extractedData;
        }
    }
}