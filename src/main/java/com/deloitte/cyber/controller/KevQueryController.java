package com.deloitte.cyber.controller;

import com.deloitte.cyber.dto.QueryRequest;
import com.deloitte.cyber.dto.QueryResponse;
import com.deloitte.cyber.service.KevAgentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/kev")
@CrossOrigin(origins = "*")
public class KevQueryController {

    private static final Logger logger = LoggerFactory.getLogger(KevQueryController.class);

    private final KevAgentService kevAgentService;

    public KevQueryController(KevAgentService kevAgentService) {
        this.kevAgentService = kevAgentService;
    }

    @PostMapping("/query")
    public ResponseEntity<?> query(@RequestBody QueryRequest request) {
        try {
            if (request.getQuestion() == null || request.getQuestion().trim().isEmpty()) {
                return ResponseEntity.badRequest().body(
                    Map.of("error", "Question cannot be empty")
                );
            }

            QueryResponse response = kevAgentService.processQuery(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error processing query", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                Map.of("error", "Failed to process query: " + e.getMessage())
            );
        }
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        try {
            Map<String, Object> status = kevAgentService.getStatus();
            return ResponseEntity.ok(status);
        } catch (Exception e) {
            logger.error("Error fetching status", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                Map.of("error", "Failed to fetch status")
            );
        }
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        Map<String, String> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "SOC KEV Agent");
        return ResponseEntity.ok(health);
    }
}