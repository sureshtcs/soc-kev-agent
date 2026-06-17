package com.deloitte.cyber.service;

import com.deloitte.cyber.domain.Vulnerability;
import com.deloitte.cyber.dto.QueryRequest;
import com.deloitte.cyber.dto.QueryResponse;
import com.deloitte.cyber.dto.VulnerabilityDTO;
import com.deloitte.cyber.repository.VulnerabilityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class KevAgentService {

    private static final Logger logger = LoggerFactory.getLogger(KevAgentService.class);

    private final QueryParserService queryParserService;
    private final AnswerSynthesisService answerSynthesisService;
    private final VulnerabilityRepository vulnerabilityRepository;
    private LocalDateTime lastCatalogRefresh;

    public KevAgentService(QueryParserService queryParserService,
                          AnswerSynthesisService answerSynthesisService,
                          VulnerabilityRepository vulnerabilityRepository) {
        this.queryParserService = queryParserService;
        this.answerSynthesisService = answerSynthesisService;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.lastCatalogRefresh = LocalDateTime.now();
    }

    public QueryResponse processQuery(QueryRequest request) {
        long startTime = System.currentTimeMillis();
        logger.info("Processing query: {}", request.getQuestion());

        // STEP 1: Parse query intent
        QueryParserService.ParsedQuery parsedQuery = queryParserService.parseQuery(request.getQuestion());
        logger.debug("Detected query type: {}", parsedQuery.type);

        // STEP 2: Retrieve relevant vulnerabilities
        List<Vulnerability> findings = retrieveVulnerabilities(parsedQuery);
        logger.debug("Retrieved {} matching vulnerabilities", findings.size());

        // STEP 3: Synthesize answer
        AnswerSynthesisService.SynthesizedAnswer synthesis = answerSynthesisService.synthesizeAnswer(
                parsedQuery.type, findings, parsedQuery
        );

        // STEP 4: Build response with traceability
        long processingTime = System.currentTimeMillis() - startTime;
        QueryResponse response = new QueryResponse(
                request.getQuestion(),
                synthesis.queryType,
                synthesis.answer,
                synthesis.findings,
                synthesis.confidence,
                buildTraceability(),
                processingTime
        );

        logger.info("Query processed in {}ms with {} findings", processingTime, findings.size());
        return response;
    }

    private List<Vulnerability> retrieveVulnerabilities(QueryParserService.ParsedQuery parsedQuery) {
        List<Vulnerability> results = new ArrayList<>();

        switch (parsedQuery.type) {
            case VENDOR_EXPOSURE:
                results = retrieveVendorExposure(parsedQuery);
                break;
            case DEADLINE:
                results = retrieveByDeadline(parsedQuery);
                break;
            case SEVERITY:
                results = retrieveBySeverity(parsedQuery);
                break;
            case RANSOMWARE:
                results = vulnerabilityRepository.findByKnownRansomwareCampaignUseTrue();
                break;
            case RECENT:
                results = vulnerabilityRepository.findRecentVulnerabilities(5);
                break;
            case TOP_VENDORS:
                results = retrieveTopVendors(parsedQuery);
                break;
            case OVERDUE:
                results = vulnerabilityRepository.findByDueDateBeforeAndDueDateIsNotNull(LocalDate.now());
                break;
            case PATCH_PRIORITY:
                results = retrievePatchPriority(parsedQuery);
                break;
            default:
                results = retrieveGeneric(parsedQuery);
        }

        return results;
    }

    private List<Vulnerability> retrieveVendorExposure(QueryParserService.ParsedQuery query) {
        String vendor = query.extractedData.get("vendor");
        if (vendor != null) {
            return vulnerabilityRepository.findByVendorProjectIgnoreCase(vendor);
        }
        return vulnerabilityRepository.findAll();
    }

    private List<Vulnerability> retrieveByDeadline(QueryParserService.ParsedQuery query) {
        String cveId = query.extractedData.get("cveId");
        if (cveId != null) {
            return vulnerabilityRepository.findByCveID(cveId)
                    .map(Collections::singletonList)
                    .orElse(Collections.emptyList());
        }
        return vulnerabilityRepository.findByDueDateAfter(LocalDate.now());
    }

    private List<Vulnerability> retrieveBySeverity(QueryParserService.ParsedQuery query) {
        List<Vulnerability> all = vulnerabilityRepository.findAll();
        return all.stream()
                .filter(v -> v.getCvssSeverity() != null && 
                       ("CRITICAL".equals(v.getCvssSeverity()) || "HIGH".equals(v.getCvssSeverity())))
                .collect(Collectors.toList());
    }

    private List<Vulnerability> retrieveTopVendors(QueryParserService.ParsedQuery query) {
        List<Object[]> vendorCounts = vulnerabilityRepository.findTopVendors(10);
        Set<String> topVendors = new HashSet<>();
        for (Object[] row : vendorCounts) {
            topVendors.add((String) row[0]);
        }

        List<Vulnerability> all = vulnerabilityRepository.findAll();
        return all.stream()
                .filter(v -> topVendors.contains(v.getVendorProject()))
                .collect(Collectors.toList());
    }

    private List<Vulnerability> retrievePatchPriority(QueryParserService.ParsedQuery query) {
        String product = query.extractedData.get("product");
        if (product != null) {
            List<Vulnerability> results = vulnerabilityRepository.findByProductIgnoreCase(product);
            return results.stream()
                    .sorted((a, b) -> {
                        if (a.getDueDate() == null) return 1;
                        if (b.getDueDate() == null) return -1;
                        return a.getDueDate().compareTo(b.getDueDate());
                    })
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    private List<Vulnerability> retrieveGeneric(QueryParserService.ParsedQuery query) {
        String keyword = query.originalQuestion;
        if (keyword.length() > 3) {
            return vulnerabilityRepository.searchByKeyword(keyword);
        }
        return Collections.emptyList();
    }

    private Map<String, Object> buildTraceability() {
        Map<String, Object> traceability = new HashMap<>();
        traceability.put("dataSource", "CISA Known Exploited Vulnerabilities");
        traceability.put("catalogSize", vulnerabilityRepository.count());
        traceability.put("lastRefresh", lastCatalogRefresh);
        traceability.put("timestamp", LocalDateTime.now());
        traceability.put("confidenceReason", "Grounded in official CISA KEV catalog with CVE traceability");
        return traceability;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "OPERATIONAL");
        status.put("catalogSize", vulnerabilityRepository.count());
        status.put("lastRefresh", lastCatalogRefresh);
        status.put("timestamp", LocalDateTime.now());
        return status;
    }
}