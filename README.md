# SOC KEV Agent - Agentic Threat Intelligence Tool

## Overview

A lightweight, production-ready Java/Spring Boot REST API that helps SOC analysts answer critical vulnerability questions with **grounded, trustworthy answers**.

**Problem:** SOC analysts spend hours manually cross-referencing CVE advisories, CISA KEV catalog, and vendor bulletins to answer simple questions like "Are we exposed to Log4Shell?" or "Which critical vulnerabilities have imminent patch deadlines?"

**Solution:** An agentic AI system that:
- Parses natural-language queries
- Retrieves + filters CISA KEV data
- Synthesizes grounded answers with full traceability
- Prioritizes trust over confidence ("No matches found" beats a wrong answer)

## Architecture

### Agentic Workflow
1. **Query Parsing** → Understand analyst intent (vendor, deadline, severity, exploits)
2. **Data Retrieval** → Fetch CISA KEV catalog + optional NIST NVD enrichment
3. **Filtering & Ranking** → Apply semantic logic to reduce noise
4. **Synthesis** → Return grounded answer with CVE metadata

### Tech Stack
- **Java 21 LTS** (with virtual threads for scalability)
- **Spring Boot 3.1.5** (REST framework)
- **H2 Database** (in-memory, fast startup)
- **Spring Cache** (reduce API calls to CISA)
- **Jackson** (JSON processing)
- **Apache Commons Text** (semantic similarity)

## Requirements

- Java 21 LTS (verified: 21.0.10+8-LTS-217)
- Maven 3.8+
- Internet access to fetch CISA KEV catalog

## Quick Start

### 1. Clone & Build
```bash
git clone https://github.com/sureshtcs/soc-kev-agent.git
cd soc-kev-agent
mvn clean install
```

### 2. Run the Application
```bash
mvn spring-boot:run
```

Server starts on `http://localhost:8080`

### 3. Test the API

#### Health Check
```bash
curl -X GET http://localhost:8080/api/kev/health
```

#### Status Check
```bash
curl -X GET http://localhost:8080/api/kev/status
```

#### Query Examples
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Which Microsoft products have actively exploited CVEs in the KEV catalog?"}'
```

## API Endpoints

### Query Endpoint (Main Interface)
```
POST /api/kev/query
Content-Type: application/json

{
  "question": "Your natural language question here"
}
```

#### Response Example
```json
{
  "question": "Which Microsoft products have actively exploited CVEs?",
  "queryType": "VENDOR_EXPOSURE",
  "answer": "Found 15 actively exploited CVE(s) in CISA KEV. The affected products are: Windows 10, Windows Server 2019, Exchange Server. Immediate patching is recommended...",
  "findings": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Microsoft",
      "product": "Windows 10",
      "shortDescription": "Log4Shell vulnerability...",
      "dateAdded": "2021-12-10",
      "dueDate": "2022-01-10",
      "cvssScore": 10.0,
      "cvssSeverity": "CRITICAL",
      "knownRansomwareCampaignUse": true
    }
  ],
  "confidence": "HIGH",
  "traceability": {
    "dataSource": "CISA Known Exploited Vulnerabilities",
    "catalogSize": 1500,
    "lastRefresh": "2024-01-15T10:30:00",
    "timestamp": "2024-01-15T10:35:00",
    "confidenceReason": "Grounded in official CISA KEV catalog with CVE traceability"
  },
  "processingTimeMs": 45
}
```

### Status Endpoint
```
GET /api/kev/status
```

Returns:
```json
{
  "status": "OPERATIONAL",
  "catalogSize": 1500,
  "lastRefresh": "2024-01-15T10:30:00",
  "timestamp": "2024-01-15T10:35:00"
}
```

### Health Endpoint
```
GET /api/kev/health
```

## Test Queries

### 1. Vendor Exposure
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Which Microsoft products have actively exploited CVEs?"}'
```

### 2. Specific CVE Deadline
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the CISA remediation deadline for CVE-2021-44228?"}'
```

### 3. Ransomware Impact
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "How many KEV entries involve ransomware campaigns?"}'
```

### 4. Recent Vulnerabilities
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "What are the 5 most recently added vulnerabilities?"}'
```

### 5. Vendor Prevalence
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Which vendors have the most entries in the KEV catalog?"}'
```

### 6. Overdue Patches
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Are there any vulnerabilities affecting Cisco IOS with a due date that has passed?"}'
```

### 7. Patch Priority
```bash
curl -X POST http://localhost:8080/api/kev/query \
  -H "Content-Type: application/json" \
  -d '{"question": "What should we patch first if we run Apache HTTP Server?"}'
```

## Design Decisions

### 1. **Agentic Workflow**
Structured as parse → retrieve → filter → synthesize to reduce hallucination. Each step is traceable and auditable.

### 2. **Trust > Confidence**
- Returns "No matching CVEs found" rather than making up matches
- Includes confidence levels and data source attribution
- Shows raw findings alongside synthesis
- Explicit "confidenceReason" in traceability

### 3. **Caching Strategy**
- CISA KEV catalog cached in H2 in-memory database
- Loaded at startup with auto-refresh capability
- Reduces external API calls, enables offline operation

### 4. **Database for Speed**
- H2 in-memory database provides millisecond-level query performance
- Multiple indexes on vendor, product, dates for fast filtering
- Can be swapped to PostgreSQL for persistent production use

### 5. **Semantic Query Parsing**
- Intent detection (8 query types supported)
- Keyword extraction for vendor/product/CVE ID
- Handles variations and loose matching
- Falls back to GENERIC search when uncertain

## Architecture Components

### Core Layers

**1. Controller Layer** (`KevQueryController`)
- REST endpoints for query submission
- Input validation
- Response formatting
- Error handling

**2. Service Layer**
- `KevAgentService`: Orchestrates query → retrieval → synthesis workflow
- `QueryParserService`: Detects intent, extracts keywords
- `AnswerSynthesisService`: Synthesizes human-readable answers
- `CisaKevService`: Manages CISA catalog fetching and caching

**3. Data Layer**
- `VulnerabilityRepository`: JPA repository with specialized queries
- `Vulnerability`: Entity model matching CISA KEV structure
- H2 database with strategic indexing

**4. DTOs**
- `QueryRequest`: Analyst question
- `QueryResponse`: Structured answer with traceability
- `VulnerabilityDTO`: Sanitized vulnerability data

## Hallucination Mitigation Strategies

1. **Grounding in Data** - All answers cite specific CVE IDs and dates
2. **Confidence Levels** - Explicit HIGH/MEDIUM/LOW confidence in responses
3. **No-Match Handling** - "No matching CVEs found" rather than invented matches
4. **Traceability** - Every answer includes:
   - Data source (CISA KEV)
   - Number of results
   - Timestamp of answer
   - Query processing time
5. **Deterministic Logic** - Query parsing and synthesis use rule-based logic, not LLMs

## Security Considerations

- No authentication on public demo endpoint (add API key/OAuth2 for production)
- CISA KEV data is public; no sensitive information exposed
- In-memory database is ephemeral; data lost on restart
- Input validation on query length and format
- CORS enabled for local testing (restrict for production)

## Future Enhancements

1. **CVSS Score Enrichment** - Pull from NIST NVD API for complete scoring
2. **Remediation Prioritization** - ML model to rank patches by business impact
3. **Threat Intelligence Integration** - Link to external TI feeds (Shodan, Censys)
4. **Batch Analysis** - Support asset list analysis ("patch these 100 servers")
5. **Alert Rules** - Trigger alerts when new CVEs match watched vendors
6. **Chat Interface** - WebSocket-based multi-turn Q&A
7. **Export Capabilities** - CSV/PDF export of findings
8. **Integration** - Webhook notifications, SIEM integration

## Monitoring & Metrics

Metrics to track:
- Response time per query
- Catalog refresh success/failure rate
- Query type distribution
- Most common vulnerabilities queried
- Cache hit rate (if Redis added)

## Deployment

### Local Development
```bash
mvn spring-boot:run
```

### JAR Package
```bash
mvn clean package
java -jar target/soc-kev-agent-1.0.0.jar
```

### Docker (Coming Soon)
```bash
docker build -t soc-kev-agent .
docker run -p 8080:8080 soc-kev-agent
```

### Production Deployment
1. Replace H2 with PostgreSQL for persistence
2. Configure persistent caching (Redis)
3. Add authentication (OAuth2/API keys)
4. Enable monitoring + alerting (Prometheus/Grafana)
5. Set up log aggregation (ELK stack)
6. Configure rate limiting
7. Add request/response logging

## License

MIT

## Contact

For questions or contributions, open an issue in the repository.