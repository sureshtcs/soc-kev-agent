package com.deloitte.cyber.service;

import com.deloitte.cyber.domain.Vulnerability;
import com.deloitte.cyber.dto.VulnerabilityDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class AnswerSynthesisService {

    private static final Logger logger = LoggerFactory.getLogger(AnswerSynthesisService.class);

    public SynthesizedAnswer synthesizeAnswer(QueryParserService.QueryType queryType, 
                                             List<Vulnerability> findings,
                                             QueryParserService.ParsedQuery parsedQuery) {

        String answer;
        String confidence;
        List<VulnerabilityDTO> dtos = findings.stream()
                .map(VulnerabilityDTO::new)
                .collect(Collectors.toList());

        if (findings.isEmpty()) {
            answer = "No matching CVEs found in the CISA Known Exploited Vulnerabilities catalog.";
            confidence = "HIGH";
            return new SynthesizedAnswer(queryType.toString(), answer, dtos, confidence);
        }

        switch (queryType) {
            case VENDOR_EXPOSURE:
                answer = synthesizeVendorExposure(findings);
                confidence = "HIGH";
                break;
            case DEADLINE:
                answer = synthesizeDeadlineAnswer(findings, parsedQuery);
                confidence = "HIGH";
                break;
            case SEVERITY:
                answer = synthesizeSeverityAnswer(findings);
                confidence = "MEDIUM";
                break;
            case RANSOMWARE:
                answer = synthesizeRansomwareAnswer(findings);
                confidence = "HIGH";
                break;
            case RECENT:
                answer = synthesizeRecentAnswer(findings);
                confidence = "HIGH";
                break;
            case TOP_VENDORS:
                answer = synthesizeTopVendorsAnswer(findings);
                confidence = "HIGH";
                break;
            case OVERDUE:
                answer = synthesizeOverdueAnswer(findings);
                confidence = "HIGH";
                break;
            case PATCH_PRIORITY:
                answer = synthesizePatchPriorityAnswer(findings);
                confidence = "MEDIUM";
                break;
            default:
                answer = synthesizeGenericAnswer(findings);
                confidence = "MEDIUM";
        }

        return new SynthesizedAnswer(queryType.toString(), answer, dtos, confidence);
    }

    private String synthesizeVendorExposure(List<Vulnerability> findings) {
        long count = findings.size();
        return String.format(
            "Found %d actively exploited CVE(s) in the CISA KEV catalog. The affected products are: %s. "
            + "Immediate patching is recommended for all CRITICAL and HIGH severity vulnerabilities.",
            count,
            findings.stream().map(Vulnerability::getProduct).distinct().limit(5).collect(Collectors.joining(", "))
        );
    }

    private String synthesizeDeadlineAnswer(List<Vulnerability> findings, QueryParserService.ParsedQuery parsedQuery) {
        if (findings.size() == 1) {
            Vulnerability v = findings.get(0);
            if (v.getDueDate() != null) {
                if (v.getDueDate().isBefore(LocalDate.now())) {
                    return String.format(
                        "%s has exceeded its CISA remediation deadline of %s. Immediate action required.",
                        v.getCveID(), v.getDueDate()
                    );
                } else {
                    long daysRemaining = java.time.temporal.ChronoUnit.DAYS.between(LocalDate.now(), v.getDueDate());
                    return String.format(
                        "%s has a CISA remediation deadline of %s (%d days remaining). Action required: %s",
                        v.getCveID(), v.getDueDate(), daysRemaining, v.getRequiredAction()
                    );
                }
            }
        }
        return String.format("Found %d vulnerabilities with remediation deadlines. See findings for details.", findings.size());
    }

    private String synthesizeSeverityAnswer(List<Vulnerability> findings) {
        long critical = findings.stream().filter(v -> "CRITICAL".equals(v.getCvssSeverity())).count();
        long high = findings.stream().filter(v -> "HIGH".equals(v.getCvssSeverity())).count();
        return String.format(
            "Severity breakdown: %d CRITICAL, %d HIGH. Prioritize patching CRITICAL vulnerabilities immediately.",
            critical, high
        );
    }

    private String synthesizeRansomwareAnswer(List<Vulnerability> findings) {
        return String.format(
            "Found %d CVE(s) with known ransomware campaign usage. These are high-priority for patching: %s",
            findings.size(),
            findings.stream().map(Vulnerability::getCveID).limit(3).collect(Collectors.joining(", "))
        );
    }

    private String synthesizeRecentAnswer(List<Vulnerability> findings) {
        return String.format(
            "The %d most recently added CVEs to CISA KEV: %s. Monitor these closely for exploit development.",
            findings.size(),
            findings.stream().map(v -> v.getCveID() + " (" + v.getDateAdded() + ")").limit(5).collect(Collectors.joining(", "))
        );
    }

    private String synthesizeTopVendorsAnswer(List<Vulnerability> findings) {
        return String.format(
            "Top affected vendors: %s have the most KEV entries. Prioritize assessments for these vendors.",
            findings.stream().map(Vulnerability::getVendorProject).distinct().limit(5).collect(Collectors.joining(", "))
        );
    }

    private String synthesizeOverdueAnswer(List<Vulnerability> findings) {
        if (findings.isEmpty()) {
            return "No vulnerabilities with overdue CISA remediation deadlines found.";
        }
        return String.format(
            "WARNING: %d CVE(s) have OVERDUE CISA remediation deadlines: %s. Immediate escalation recommended.",
            findings.size(),
            findings.stream().map(v -> v.getCveID() + " (due " + v.getDueDate() + ")").limit(5).collect(Collectors.joining(", "))
        );
    }

    private String synthesizePatchPriorityAnswer(List<Vulnerability> findings) {
        if (findings.isEmpty()) {
            return "No vulnerabilities found for the specified product.";
        }
        Vulnerability priority = findings.stream()
                .filter(v -> v.getDueDate() != null)
                .min((a, b) -> a.getDueDate().compareTo(b.getDueDate()))
                .orElse(findings.get(0));

        return String.format(
            "PATCH PRIORITY: %s (%s) - Due: %s. Required action: %s. Followed by %d additional CVE(s).",
            priority.getCveID(),
            priority.getProduct(),
            priority.getDueDate(),
            priority.getRequiredAction(),
            findings.size() - 1
        );
    }

    private String synthesizeGenericAnswer(List<Vulnerability> findings) {
        return String.format(
            "Found %d matching CVE(s). See findings details for full information including CVE ID, vendor, product, CVSS score, and CISA due date.",
            findings.size()
        );
    }

    public static class SynthesizedAnswer {
        public final String queryType;
        public final String answer;
        public final List<VulnerabilityDTO> findings;
        public final String confidence;

        public SynthesizedAnswer(String queryType, String answer, List<VulnerabilityDTO> findings, String confidence) {
            this.queryType = queryType;
            this.answer = answer;
            this.findings = findings;
            this.confidence = confidence;
        }
    }
}