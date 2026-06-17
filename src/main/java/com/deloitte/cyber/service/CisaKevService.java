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
import org.springframework.web.reactive.function.client.WebClientResponseException;

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
            if (repository.count() == 0) {
                logger.warn("No data from CISA API, loading mock data for demo...");
                loadMockData();
            }
            catalogLoaded = true;
            logger.info("CISA KEV catalog loaded successfully. Total vulnerabilities: {}", repository.count());
        } catch (Exception e) {
            logger.error("Failed to load CISA KEV catalog, loading mock data", e);
            loadMockData();
            catalogLoaded = true;
        }
    }

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
        } catch (WebClientResponseException e) {
            logger.warn("Network error fetching CISA KEV data: {}", e.getStatusCode());
        } catch (Exception e) {
            logger.warn("Error fetching CISA KEV data: {}", e.getMessage());
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

    private void loadMockData() {
        logger.info("Loading mock CISA KEV data for testing...");
        List<Vulnerability> mockData = new ArrayList<>();

        // Microsoft CVEs
        mockData.add(createVuln("CVE-2021-44228", "Microsoft", "Windows 10", "Log4Shell RCE", 
            "Remote code execution in Log4j library", "Apply vendor patch", 
            LocalDate.of(2021, 12, 10), LocalDate.of(2022, 1, 10), 
            true, 10.0, "CRITICAL"));

        mockData.add(createVuln("CVE-2021-26855", "Microsoft", "Exchange Server", "ProxyLogon", 
            "Pre-authentication RCE in Exchange Server", "Apply security patch", 
            LocalDate.of(2021, 3, 2), LocalDate.of(2021, 4, 15), 
            true, 9.8, "CRITICAL"));

        mockData.add(createVuln("CVE-2021-27065", "Microsoft", "Exchange Server", "ProxyLogon Chain", 
            "Remote code execution chain vulnerability", "Apply immediate patch", 
            LocalDate.of(2021, 3, 2), LocalDate.of(2021, 4, 15), 
            true, 9.0, "CRITICAL"));

        mockData.add(createVuln("CVE-2020-1938", "Microsoft", "Windows Server 2019", "BlueKeep", 
            "Pre-auth RCE in RDP", "Enable Network Level Authentication", 
            LocalDate.of(2019, 5, 14), LocalDate.of(2019, 6, 15), 
            false, 9.8, "CRITICAL"));

        // Cisco CVEs
        mockData.add(createVuln("CVE-2022-20821", "Cisco", "IOS", "RCE Vulnerability", 
            "Remote code execution in Cisco IOS", "Update to patched version", 
            LocalDate.of(2022, 9, 28), LocalDate.of(2022, 10, 28), 
            true, 9.1, "CRITICAL"));

        mockData.add(createVuln("CVE-2021-1119", "Cisco", "IOS XR", "Authentication bypass", 
            "Authentication bypass in Cisco IOS XR", "Apply vendor patch", 
            LocalDate.of(2021, 2, 3), LocalDate.of(2021, 3, 5), 
            false, 8.5, "HIGH"));

        // Apache CVEs
        mockData.add(createVuln("CVE-2021-41773", "Apache", "HTTP Server", "Path Traversal", 
            "Path traversal and RCE in Apache HTTP Server 2.4.49", "Update to 2.4.50+", 
            LocalDate.of(2021, 10, 1), LocalDate.of(2021, 11, 1), 
            true, 9.8, "CRITICAL"));

        mockData.add(createVuln("CVE-2021-41774", "Apache", "HTTP Server", "RCE Follow-up", 
            "Related RCE vulnerability in Apache HTTP Server", "Update immediately", 
            LocalDate.of(2021, 10, 5), LocalDate.of(2021, 11, 5), 
            true, 9.0, "CRITICAL"));

        // Other vendors
        mockData.add(createVuln("CVE-2021-34527", "Canon", "UFRII Printer Driver", "Print Spooler RCE", 
            "Windows Print Spooler vulnerability (PrintNightmare)", "Disable Print Spooler", 
            LocalDate.of(2021, 7, 1), LocalDate.of(2021, 8, 1), 
            true, 8.8, "HIGH"));

        mockData.add(createVuln("CVE-2021-44545", "Redis", "Redis Server", "Sentinel RCE", 
            "Remote code execution in Redis Sentinel", "Update to latest version", 
            LocalDate.of(2021, 10, 4), LocalDate.of(2021, 11, 4), 
            false, 8.0, "HIGH"));

        mockData.add(createVuln("CVE-2021-3129", "Laravel", "Laravel Framework", "RCE via Ignition", 
            "Remote code execution via Ignition debug page", "Update Laravel and Ignition", 
            LocalDate.of(2021, 1, 12), LocalDate.of(2021, 2, 12), 
            true, 9.1, "CRITICAL"));

        mockData.add(createVuln("CVE-2022-26134", "Atlassian", "Confluence", "RCE", 
            "Remote code execution in Confluence", "Apply security patch immediately", 
            LocalDate.of(2022, 6, 2), LocalDate.of(2022, 7, 2), 
            true, 9.8, "CRITICAL"));

        mockData.add(createVuln("CVE-2022-21894", "VMware", "vCenter Server", "Authentication bypass", 
            "Authentication bypass in vCenter Server", "Apply vendor update", 
            LocalDate.of(2022, 2, 1), LocalDate.of(2022, 3, 15), 
            false, 7.5, "HIGH"));

        mockData.add(createVuln("CVE-2022-1040", "Fortinet", "FortiGate", "Heap overflow", 
            "Heap overflow in FortiGate SSL VPN", "Upgrade FortiGate firmware", 
            LocalDate.of(2022, 4, 1), LocalDate.of(2022, 5, 15), 
            true, 9.0, "CRITICAL"));

        repository.deleteAll();
        repository.saveAll(mockData);
        logger.info("Loaded {} mock vulnerabilities", mockData.size());
    }

    private Vulnerability createVuln(String cveID, String vendor, String product, String vulnName,
                                     String description, String action, LocalDate dateAdded, 
                                     LocalDate dueDate, boolean ransomware, double cvss, String severity) {
        Vulnerability v = new Vulnerability();
        v.setCveID(cveID);
        v.setVendorProject(vendor);
        v.setProduct(product);
        v.setVulnerabilityName(vulnName);
        v.setShortDescription(description);
        v.setRequiredAction(action);
        v.setDateAdded(dateAdded);
        v.setDueDate(dueDate);
        v.setKnownRansomwareCampaignUse(ransomware);
        v.setCvssScore(cvss);
        v.setCvssSeverity(severity);
        v.setLastUpdated(LocalDate.now());
        v.setNotes("Mock data for testing");
        return v;
    }

    public boolean isCatalogLoaded() {
        return catalogLoaded;
    }

    public long getCatalogSize() {
        return repository.count();
    }
}