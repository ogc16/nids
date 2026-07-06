# NIDS Workspace

A **Network Intrusion Detection System** SOC workspace — a full-stack security operations dashboard built with Node.js, Express, vanilla JS, and Chart.js.

## Features

### Security Operations
- **Dashboard** — Real-time metrics, severity/status/attack-type charts, stat cards
- **Incidents & Alerts** — Filterable board with severity groups, detail modals, search
- **Detection Rules** — Grouped by status (Active / In Development / Deprecated), linked to tasks
- **Threat Intelligence** — CVEs, IOC tracking, risk scoring, and status management

### Engineering & QA
- **Engineering Tasks** — Sprint-based task board with assignee/sprint filtering, linked to rules
- **QA & Testing Board** — Test case management for detection rules before production deployment

### Infrastructure & Monitoring
- **Network Assets** — Device inventory with risk levels, health status, and grouping
- **Network Monitoring** — Real-time traffic flow viewer with protocol distribution charts, suspicious/blocked flow highlighting, country-level detail, and **Wireshark display filter** support
- **PCAP Analysis** — Upload and analyze packet capture files via tshark: protocol hierarchy, endpoint statistics, conversations, packet-level browsing with display filters, pagination, and PCAP export
- **Host Monitoring** — Real-time system health and network diagnostics: active TCP/UDP connections, listening ports with process details, bandwidth per interface, ARP table, DNS cache, routing table, subnet network scan

### Patch Management
- **Patch Status** — View installed Windows hotfixes with KB IDs, install dates, descriptions
- **Windows Update Scan** — Scan for pending updates via Windows Update API
- **Install Updates** — Trigger patch installation for specific KBs
- **Audit Log** — Track all patch management activity with timestamps

### Compliance & Security Frameworks
- **PCI-DSS, HIPAA, GDPR** — Compliance status dashboards with control-level breakdowns
- **MITRE ATT&CK** — Tactic/technique matrices, coverage analysis, and heatmaps
- **Snort/Suricata Rules** — Rule validation, parsing, conversion, and correlation

### Automations Engine
- **Critical Severity Alert** — Auto-logs when a Critical incident is created or updated
- **Incident Resolved Notification** — Logs when resolved incidents carry CVSS scores
- **CI/CD Rule Promotion** — When an Engineering Task linked to a rule is marked Done, the rule auto-promotes from "In Development" to "Active"
- **SOAR Playbooks** — Built-in and custom playbook execution with tracking
- **Alerting Channels** — Email, Slack, and webhook notification configuration

### Threat Detection
- **ML Anomaly Detection** — Model training, prediction, and anomaly scoring on traffic data
- **File Integrity Monitoring** — Baseline/scan/watch workflows with change reports
- **Vulnerability Scanning** — Asset assessment, CVE database queries, and scan reports
- **Data Retention** — Policy-based archiving, legal holds, and storage forecasting

## Tech Stack

| Layer    | Technology |
|----------|-----------|
| Backend  | Node.js, Express 5 |
| Frontend | Vanilla JS, Chart.js 4 |
| Styling  | Custom CSS (dark SOC theme) |
| Data     | JSON file-based storage |
| Testing  | Node.js HTTP test suite |
| PCAP     | tshark (Wireshark CLI) 4.x |
| Host OS  | Windows (PowerShell-based monitoring) |

## Project Structure

```
nids/
├── server.js                 # Thin entry point — boots app + TLS listeners
├── app.js                    # Express app setup — middleware, CSRF, routing, error handlers
├── package.json
├── test-api.js               # API test suite
├── routes/                   # Modular route handlers (one per domain)
│   ├── index.js              # Router composer — mounts all modules
│   ├── auth.js               # Login, logout, user management
│   ├── crud.js               # Generic CRUD for all data tables
│   ├── traffic.js            # Network traffic flows, web traffic analytics, simulation
│   ├── stats.js              # Dashboard stats, SSE streaming, metrics
│   ├── pcap.js               # PCAP upload, analysis, live capture
│   ├── monitor.js            # Host monitoring (connections, ports, ARP, scan)
│   ├── mitre.js              # MITRE ATT&CK tactics/techniques/matrix
│   ├── syslog.js             # Syslog collection and forwarding
│   ├── snort.js              # Snort rule parsing, validation, conversion
│   ├── agents.js             # Agent management (register, collect, deploy)
│   ├── soar.js               # SOAR playbook execution
│   ├── fim.js                # File integrity monitoring
│   ├── vulnscan.js           # Vulnerability scanning and assessment
│   ├── compliance.js         # PCI-DSS / HIPAA / GDPR compliance frameworks
│   ├── ml.js                 # ML model training and anomaly detection
│   ├── retention.js          # Data retention policies and archiving
│   ├── alerting.js           # Alerting configurations (email/slack/webhook)
│   ├── automations.js        # Automation engine, logs, triggers
│   ├── setup.js              # Settings, seed data, audit logs, health
│   ├── network.js            # Network asset scanning and IPAM
│   ├── sse.js                # Server-Sent Events broadcast hub
│   └── extra.js              # Search, customer report, CSF, asset logs
├── lib/                      # Backend modules
│   ├── auth.js               # JWT authentication & cookie sessions
│   ├── config.js             # Server configuration
│   ├── db.js                 # JSON file-based data store
│   ├── pcap.js               # tshark PCAP analysis & live capture
│   ├── monitor.js            # PowerShell host monitoring
│   ├── patch.js              # Windows update management
│   ├── mitre.js              # MITRE ATT&CK data model
│   ├── snort.js              # Snort rule parsing/generation
│   ├── soar.js               # SOAR playbook engine
│   ├── fim.js                # File integrity monitoring
│   ├── vulnscan.js           # Vulnerability scanning engine
│   ├── compliance.js         # Compliance framework state
│   ├── ml.js                 # ML anomaly detection models
│   ├── retention.js          # Data retention policies
│   ├── alerting.js           # Notification dispatch
│   ├── agent.js              # Agent communication protocol
│   ├── syslog.js             # Syslog server and forwarding
│   ├── audit.js              # Audit logging
│   ├── errors.js             # Error handling utilities
│   ├── tls.js                # TLS certificate loading
│   └── validate.js           # Input validation
├── data/                     # JSON-backed data store
│   ├── incidents.json
│   ├── detection-rules.json
│   ├── threat-intel.json
│   ├── engineering-tasks.json
│   ├── network-assets.json
│   ├── network-traffic.json
│   ├── qa-tests.json
│   ├── automations-log.json
│   ├── pcap-captures.json
│   ├── alerting-config.json
│   ├── compliance.json
│   ├── fim-baselines.json
│   ├── model-results.json
│   ├── retention-policies.json
│   ├── syslog-sources.json
│   └── users.json
├── data/pcap/                # Uploaded PCAP capture files
└── public/                   # Static frontend
    ├── styles.css            # Dark SOC theme (1000+ lines)
    ├── app.js                # Shared utilities (apiFetch, toast, modal, etc.)
    ├── index.html + dashboard.js
    ├── incidents.html + incidents.js
    ├── rules.html + rules.js
    ├── threat-intel.html + threat-intel.js
    ├── tasks.html + tasks.js
    ├── assets.html + assets.js
    ├── network-monitoring.html + network-monitoring.js
    ├── web-traffic.html + web-traffic.js
    ├── pcap-analysis.html + pcap-analysis.js
    ├── host-monitoring.html + host-monitoring.js
    ├── qa.html + qa.js
    ├── customer-report.html + customer-report.js
    ├── report-incident.html
    └── submit-rule.html
```

## API Endpoints

### CRUD (all tables support full REST)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/:table` | List all records |
| GET | `/api/:table/:id` | Get single record |
| POST | `/api/:table` | Create record |
| PUT | `/api/:table/:id` | Update record |
| DELETE | `/api/:table/:id` | Delete record |

**Tables**: `incidents`, `detection-rules`, `threat-intel`, `engineering-tasks`, `network-assets`, `network-traffic`, `qa-tests`

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login (returns JWT + sets HTTP-only cookie + CSRF token) |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Current user info |
| PUT | `/api/auth/change-password` | Change password |

### Dashboard & Stats
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Aggregated dashboard stats |
| GET | `/api/realtime` | SSE streaming endpoint for live updates |
| GET | `/api/customer-report` | Resolved incidents with CVSS |
| GET | `/api/db/stats` | Database collection sizes |

### Network Traffic
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/network-traffic` | Traffic flows with optional `?displayFilter=` |
| GET | `/api/network-traffic/stats` | Traffic flow summary stats |
| POST | `/api/network-traffic/simulate` | Generate simulated traffic |
| POST | `/api/network-traffic/auto-simulate` | Start/stop periodic auto-simulation |
| GET | `/api/network-traffic/export` | Download CSV export |

### Web Traffic
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/web-traffic/summary` | HTTP traffic summary |
| GET | `/api/web-traffic/requests` | Paginated HTTP request log |
| GET | `/api/web-traffic/top-uris` | Top 20 URIs |
| GET | `/api/web-traffic/top-hosts` | Top 20 hosts |
| GET | `/api/web-traffic/errors` | Error analysis (4xx/5xx) |
| GET | `/api/web-traffic/export` | Download CSV |

### PCAP Analysis
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/pcap/upload` | Upload a PCAP file |
| GET | `/api/pcap/captures` | List all uploaded captures |
| GET | `/api/pcap/captures/:id` | Get capture metadata |
| DELETE | `/api/pcap/captures/:id` | Delete a capture |
| GET | `/api/pcap/captures/:id/analysis/protocols` | Protocol hierarchy |
| GET | `/api/pcap/captures/:id/analysis/endpoints` | Endpoint statistics |
| GET | `/api/pcap/captures/:id/analysis/conversations` | Conversation statistics |
| GET | `/api/pcap/captures/:id/analysis/packets` | Packet listing (paginated, filterable) |
| GET | `/api/pcap/captures/:id/export` | Download raw PCAP file |
| POST | `/api/pcap/validate-filter` | Validate a Wireshark display filter syntax |
| GET | `/api/pcap/status` | tshark availability & config status |

### Live Capture
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/capture/interfaces` | List available network interfaces |
| POST | `/api/capture/start` | Start a live capture on an interface |
| POST | `/api/capture/stop` | Stop the active capture |
| GET | `/api/capture/active` | Check if a capture is running |

### Host Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/monitor/system` | System info (hostname, uptime, CPU, memory) |
| GET | `/api/monitor/connections` | Active TCP/UDP connections with process info |
| GET | `/api/monitor/ports` | Listening ports with process details |
| GET | `/api/monitor/process/:pid` | Detailed process info |
| GET | `/api/monitor/interfaces` | Network interface cards |
| GET | `/api/monitor/bandwidth` | Interface bandwidth statistics |
| GET | `/api/monitor/arp` | ARP table |
| GET | `/api/monitor/dns-cache` | DNS client cache |
| GET | `/api/monitor/routing-table` | IP routing table |
| POST | `/api/monitor/scan` | Subnet ping sweep scan |
| GET | `/api/monitor/network/discovery` | Combined ARP + routing + interfaces |

### Patch Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/patch/hotfixes` | List installed Windows hotfixes |
| GET | `/api/patch/updates` | Scan for pending Windows updates |
| POST | `/api/patch/install` | Install a specific update by KB ID |
| GET | `/api/patch/log` | View patch audit log |

### MITRE ATT&CK
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/mitre/tactics` | All tactics with technique counts |
| GET | `/api/mitre/techniques` | Techniques filtered by tactic, platform, query |
| GET | `/api/mitre/coverage` | Detection coverage analysis |
| GET | `/api/mitre/matrix` | Full ATT&CK matrix |
| GET | `/api/mitre/analysis` | Coverage by tactic with percentages |

### Snort Rules
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/snort/validate` | Validate a Snort rule syntax |
| POST | `/api/snort/parse` | Parse rule into structured object |
| POST | `/api/snort/convert` | Convert between Suricata and Snort format |
| POST | `/api/snort/correlate` | Correlate a rule against incident data |
| GET | `/api/snort/sample` | Generate sample rules for a category |

### SOAR Playbooks
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/soar/playbooks` | List built-in playbooks |
| POST | `/api/soar/playbooks/:id/execute` | Execute a playbook |
| GET | `/api/soar/executions` | Execution history |
| GET | `/api/soar/executions/:id` | Execution detail |

### File Integrity Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/fim/baseline` | Create a file baseline |
| POST | `/api/fim/scan` | Run a scan against a baseline |
| POST | `/api/fim/watch` | Start/stop a real-time watch |
| GET | `/api/fim/config` | Current FIM configuration |
| GET | `/api/fim/report` | Latest scan report |

### Vulnerability Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/vulnscan/scan` | Run a vulnerability scan against a target |
| POST | `/api/vulnscan/assess-asset` | Assess a specific asset |
| GET | `/api/vulnscan/db` | Query the CVE database |
| GET | `/api/vulnscan/report` | Latest scan report |
| GET | `/api/vulnscan/results` | Scan results history |

### Compliance
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/compliance/frameworks` | All frameworks with status |
| GET | `/api/compliance/dashboard` | Compliance dashboard overview |
| GET | `/api/compliance/recommendations` | Remediation plans |
| GET | `/api/compliance/evidence/:framework/:controlId` | Evidence collection |
| GET | `/api/compliance/:framework` | Framework-specific status |
| GET | `/api/compliance/:framework/controls` | Framework controls |
| GET | `/api/compliance/:framework/report` | Framework report |

### ML / Anomaly Detection
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ml/models` | Available ML models |
| POST | `/api/ml/train` | Train a model on traffic data |
| POST | `/api/ml/predict` | Run prediction on traffic data |
| POST | `/api/ml/anomalies/detect` | Detect anomalies in traffic |
| GET | `/api/ml/anomalies/history` | Anomaly detection history |

### Data Retention
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/retention/policies` | List retention policies |
| POST | `/api/retention/policies` | Create a retention policy |
| PUT | `/api/retention/policies/:id` | Update a policy |
| DELETE | `/api/retention/policies/:id` | Delete a policy |
| POST | `/api/retention/archive` | Trigger archiving |
| GET | `/api/retention/legal-holds` | List legal holds |
| POST | `/api/retention/legal-holds` | Place a legal hold |
| GET | `/api/retention/forecast` | Storage forecast |

### Alerting
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerting/config` | Alerting configuration |
| PUT | `/api/alerting/config` | Update configuration |
| POST | `/api/alerting/test/email` | Test email notification |
| POST | `/api/alerting/test/slack` | Test Slack notification |
| POST | `/api/alerting/test/webhook` | Test webhook notification |

### Automations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/automations/log` | Automation event history |
| GET | `/api/automations/status` | Automation engine status |
| GET | `/api/automations/metrics` | Automation metrics |
| POST | `/api/automations/trigger/severity-critical` | Fire critical alerts |
| POST | `/api/automations/trigger/resolved-asset-update` | Link resolved incidents to assets |

### Agents
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agents` | List registered agents |
| POST | `/api/agents/register` | Register a new agent |
| POST | `/api/agents/discover` | Discover agents on network |
| POST | `/api/agents/collect/:id` | Collect data from an agent |
| POST | `/api/agents/server/start` | Start agent listener |
| POST | `/api/agents/server/stop` | Stop agent listener |

### Network Assets
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/network-assets` | List assets with optional scan |
| POST | `/api/network-assets/scan` | Scan subnet for new assets |
| GET | `/api/network-assets/:ip` | Get asset by IP |

### Syslog
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/syslog/sources` | List syslog sources |
| POST | `/api/syslog/sources` | Add a syslog source |
| GET | `/api/syslog/sources/:id` | Get source details |
| PUT | `/api/syslog/sources/:id` | Update a source |
| DELETE | `/api/syslog/sources/:id` | Delete a source |
| POST | `/api/syslog/server/start` | Start syslog listener |
| POST | `/api/syslog/server/stop` | Stop syslog listener |
| GET | `/api/syslog/events` | Recent syslog events |
| POST | `/api/syslog/forward` | Configure forwarding |

## Architecture

```
Browser ──HTTP/HTTPS──> Express (app.js) ── routes/index.js ──> lib/ modules ──fs──> JSON files
                            │                                              │
                      helmet / cors /                              20 modules for:
                      rate-limit /                                  PCAP, monitor, patch,
                      CSRF cookie                                   MITRE, Snort, SOAR,
                                                                     FIM, vulnscan, ML,
                                                                     compliance, syslog,
                                                                     agents, alerting,
                                                                     retention, audit...
```

`server.js` is a ~20-line entry point that loads `app.js` and starts HTTP/HTTPS listeners. All business logic lives in `lib/`, all route handlers in `routes/`.

## Getting Started

### Prerequisites
- Node.js 18+
- Wireshark/tshark 4.x (optional, for PCAP analysis)
- Npcap (optional, for live packet capture on Windows)

### Install & Run
```bash
cd nids
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000)

### Default Login
First run generates a random admin password (printed to console). For testing:
- Username: `admin`
- Password: `admin123`

### Run Tests
```bash
npm test
```

Requires the server to be running.

## Data Model

### Incidents
| Field | Type | Description |
|-------|------|-------------|
| id | number | Primary key |
| title | string | Incident summary |
| severity | string | Critical / High / Medium / Low |
| status | string | New / Investigating / Resolved / Closed |
| sourceIp | string | Attacker IP |
| attackType | string | C2, SQL Injection, Malware, etc. |
| assignee | string | Owner |
| detectedAt | ISO date | When detected |
| resolutionNotes | string | Close-out notes |
| ruleId | number? | Linked detection rule |
| cvssScore | number? | CVSS v3 score (0-10) |

### Detection Rules
| Field | Type | Description |
|-------|------|-------------|
| id | number | Primary key |
| name | string | Rule name |
| status | string | Active / In Development / Deprecated |
| protocol | string | TCP, UDP, HTTP, DNS, etc. |
| threatCategory | string | C2, Malware, Brute Force, etc. |
| priority | string | Critical / High / Medium / Low |
| falsePositiveRate | number | FP percentage |
| lastUpdated | date | Last modification |

### Engineering Tasks
| Field | Type | Description |
|-------|------|-------------|
| id | number | Primary key |
| taskName | string | Task description |
| status | string | To Do / In Progress / Done |
| priority | string | Critical / High / Medium / Low |
| assignee | string | Owner |
| sprint | string | Sprint label |
| estimatedHours | number | Effort estimate |
| dueDate | date | Deadline |
| ruleId | number? | Linked detection rule |

### Network Traffic
| Field | Type | Description |
|-------|------|-------------|
| id | number | Primary key |
| srcIp | string | Source IP |
| destIp | string | Destination IP |
| srcPort | number | Source port |
| destPort | number | Destination port |
| protocol | string | HTTP, HTTPS, DNS, SSH, SMB, etc. |
| bytes | number | Total bytes transferred |
| packets | number | Packet count |
| duration | number | Flow duration (seconds) |
| timestamp | ISO date | When captured |
| status | string | allowed / blocked / suspicious |
| application | string | Web, DNS, Email, SCADA, etc. |
| assetId | number? | Linked network asset |
| ruleId | number? | Triggered detection rule |
| country | string | Geo-location code |

## Automation Rules

The server runs automation hooks on `POST` and `PUT` events:

1. **Critical Severity → Alert**: When an incident is created/updated with severity `Critical` and the status is open, an automation log entry is created
2. **Incident Resolved with CVSS**: Resolved incidents with a CVSS score are automatically logged for the customer report
3. **CI/CD Rule Promotion**: When an engineering task linked to a rule (`task.ruleId`) transitions to `Done`, the linked rule auto-promotes from `In Development` to `Active`
