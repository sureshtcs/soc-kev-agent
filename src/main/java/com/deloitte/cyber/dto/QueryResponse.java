package com.deloitte.cyber.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class QueryResponse {
    private String question;
    private String queryType;
    private String answer;
    private List<VulnerabilityDTO> findings;
    private String confidence;
    private Map<String, Object> traceability;
    private long processingTimeMs;

    public QueryResponse() {}

    public QueryResponse(String question, String queryType, String answer, List<VulnerabilityDTO> findings,
                         String confidence, Map<String, Object> traceability, long processingTimeMs) {
        this.question = question;
        this.queryType = queryType;
        this.answer = answer;
        this.findings = findings;
        this.confidence = confidence;
        this.traceability = traceability;
        this.processingTimeMs = processingTimeMs;
    }

    public String getQuestion() { return question; }
    public void setQuestion(String question) { this.question = question; }

    public String getQueryType() { return queryType; }
    public void setQueryType(String queryType) { this.queryType = queryType; }

    public String getAnswer() { return answer; }
    public void setAnswer(String answer) { this.answer = answer; }

    public List<VulnerabilityDTO> getFindings() { return findings; }
    public void setFindings(List<VulnerabilityDTO> findings) { this.findings = findings; }

    public String getConfidence() { return confidence; }
    public void setConfidence(String confidence) { this.confidence = confidence; }

    public Map<String, Object> getTraceability() { return traceability; }
    public void setTraceability(Map<String, Object> traceability) { this.traceability = traceability; }

    public long getProcessingTimeMs() { return processingTimeMs; }
    public void setProcessingTimeMs(long processingTimeMs) { this.processingTimeMs = processingTimeMs; }
}