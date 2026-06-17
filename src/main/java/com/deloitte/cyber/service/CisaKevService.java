package com.deloitte.cyber.service;

import com.deloitte.cyber.domain.Vulnerability;
import com.deloitte.cyber.repository.VulnerabilityRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@Service
public class CisaKevService {

    private static final Logger logger = LoggerFactory.getLogger(CisaKevService.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE;

    @Value("${cisa.kev.url}")
    private String cisaKevUrl;

    private final VulnerabilityRepository repository;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private boolean catalogLoaded = false;

    public CisaKevService(VulnerabilityRepository repository, WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
        this.repository = repository;
        this.webClient = webClientBuilder.build();
        this.objectMapper = objectMapper;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void loadCisaKevCatalog() {
        logger.info("Loading CISA KEV catalog on application startup...");
        try {
            fetchAndStoreCisaData();
            catalogLoaded = true;
            logger.info("CISA KEV catalog loaded successfully. Total vulnerabilities: {}", repository.count());
        } catch (Exception e) {
            logger.error("Failed to load CISA KEV catalog", e);
        }
    }

    @Cacheable("cisaKevCatalog")
    public void fetchAndStoreCisaData() {
        try {
            String response = webClient.get()
                    .uri(cisaKevUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            if (response != null) {
                JsonNode root = objectMapper.readTree(response);
                JsonNode vulnerabilities = root.get("vulnerabilities");

                if (vulnerabilities != null && vulnerabilities.isArray()) {
                    List<Vulnerability> vulnList = new ArrayList<>();

                    for (JsonNode node : vulnerabilities) {
                        Vulnerability vuln = parseVulnerability(node);
                        if (vuln != null) {
                            vulnList.add(vuln);
                        }
                    }

                    // Clear existing data and save new
                    repository.deleteAll();
                    repository.saveAll(vulnList);
                    logger.info("Loaded {} vulnerabilities from CISA KEV catalog", vulnList.size());
                }
            }
        } catch (Exception e) {
            logger.error("Error fetching CISA KEV data", e);
        }
    }

    private Vulnerability parseVulnerability(JsonNode node) {
        try {
            Vulnerability vuln = new Vulnerability();
            vuln.setCveID(node.get("cveID").asText());
            vuln.setVendorProject(node.get("vendorProject").asText());
            vuln.setProduct(node.get("product").asText());
            vuln.setVulnerabilityName(node.get("vulnerabilityName").asText(""));
            vuln.setShortDescription(node.get("shortDescription").asText(""));
            vuln.setRequiredAction(node.get("requiredAction").asText(""));

            if (node.has("dateAdded")) {
                vuln.setDateAdded(LocalDate.parse(node.get("dateAdded").asText(), DATE_FORMATTER));
            }

            if (node.has("dueDate")) {
                vuln.setDueDate(LocalDate.parse(node.get("dueDate").asText(), DATE_FORMATTER));
            }

            vuln.setKnownRansomwareCampaignUse(node.has("knownRansomwareCampaignUse") && node.get("knownRansomwareCampaignUse").asBoolean(false));
            vuln.setNotes(node.get("notes").asText(""));
            vuln.setLastUpdated(LocalDate.now());

            // Default severity if not available from CISA
            vuln.setCvssScore(9.0);
            vuln.setCvssSeverity("HIGH");

            return vuln;
        } catch (Exception e) {
            logger.warn("Error parsing vulnerability node", e);
            return null;
        }
    }

    public boolean isCatalogLoaded() {
        return catalogLoaded;
    }

    public long getCatalogSize() {
        return repository.count();
    }
}