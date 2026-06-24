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
- **QA & Testing Board** — Test case management for detection rules before production deployment. Promote passed tests to Active via CI/CD pipeline

### Infrastructure & Monitoring
- **Network Assets** — Device inventory with risk levels, health status, and grouping
- **Network Monitoring** — Real-time traffic flow viewer with protocol distribution charts, suspicious/blocked flow highlighting, country-level detail, and **Wireshark display filter** support
- **PCAP Analysis** — Upload and analyze packet capture files via Wireshark/tshark: protocol hierarchy, endpoint statistics, conversations, packet-level browsing with display filters, pagination, and PCAP export
- **Host Monitoring** — Real-time system health and network diagnostics: active TCP/UDP connections, listening ports with process details, bandwidth per interface, ARP table, DNS cache, routing table, subnet network scan

### Patch Management
- **Patch Status** — View installed Windows hotfixes with KB IDs, install dates, descriptions
- **Windows Update Scan** — Scan for pending updates via Windows Update API
- **Install Updates** — Trigger patch installation for specific KBs
- **Audit Log** — Track all patch management activity with timestamps

### Reports
- **Customer Report** — Client-ready filtered view showing only resolved incidents with CVSS scores, resolution times, and attack-type breakdowns

### Automations Engine
- **Critical Severity Alert** — Auto-logs when a Critical incident is created or updated
- **Incident Resolved Notification** — Logs when resolved incidents carry CVSS scores
- **CI/CD Rule Promotion** — When an Engineering Task linked to a rule is marked Done, the rule auto-promotes from "In Development" to "Active"
- **Manual Triggers** — REST endpoints to fire automations on demand

## Tech Stack

| Layer    | Technology |
|----------|-----------|
| Backend  | Node.js, Express |
| Frontend | Vanilla JS, Chart.js 4 |
| Styling  | Custom CSS (dark SOC theme) |
| Data     | JSON file-based storage |
| Testing  | Node.js HTTP test suite |
| PCAP     | tshark (Wireshark CLI) 4.x |
| Host OS  | Windows (PowerShell-based monitoring) |

## Project Structure

```
nids/
├── server.js                 # Express API server with CRUD + automations
├── package.json
├── test-api.js               # API test suite (36 tests)
├── lib/                      # Backend modules
│   ├── pcap.js               # tshark-based PCAP analysis & live capture
│   ├── monitor.js            # PowerShell host monitoring (connections, ports, ARP, scan)
│   ├── auth.js               # Authentication & cookie-based session
│   └── config.js             # Server configuration
├── data/                     # JSON-backed data store
│   ├── incidents.json
│   ├── detection-rules.json
│   ├── threat-intel.json
│   ├── engineering-tasks.json
│   ├── network-assets.json
│   ├── network-traffic.json
│   ├── qa-tests.json
│   └── automations-log.json
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

### Special Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Aggregated dashboard stats |
| GET | `/api/customer-report` | Resolved incidents with CVSS |
| GET | `/api/network-traffic/stats` | Traffic flow summary stats |
| GET | `/api/network-traffic` | Traffic flows with optional `?displayFilter=` |
| GET | `/api/automations/log` | Automation event history |
| POST | `/api/automations/trigger/severity-critical` | Fire critical alerts |
| POST | `/api/automations/trigger/resolved-asset-update` | Link resolved incidents to assets |

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
| GET | `/api/monitor/connections` | Active TCP/UDP connections with process info |
| GET | `/api/monitor/ports` | Listening ports with process details |
| GET | `/api/monitor/process/:pid` | Detailed process info (memory, threads, CPU) |
| GET | `/api/monitor/interfaces` | Network interface cards |
| GET | `/api/monitor/system` | System info (hostname, uptime, CPU, memory) |
| GET | `/api/monitor/bandwidth` | Interface bandwidth statistics |
| GET | `/api/monitor/arp` | ARP table |
| GET | `/api/monitor/dns-cache` | DNS client cache |
| GET | `/api/monitor/routing-table` | IP routing table |
| POST | `/api/monitor/scan` | Subnet ping sweep scan |

### Patch Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/patch/hotfixes` | List installed Windows hotfixes |
| GET | `/api/patch/updates` | Scan for pending Windows updates |
| POST | `/api/patch/install` | Install a specific update by KB ID |
| GET | `/api/patch/log` | View patch audit log |

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login (returns JWT + sets HTTP-only cookie) |
| POST | `/api/auth/logout` | Logout |

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
- Username: `admin`
- Password: `admin`

### Run Tests
```bash
npm test
```

Requires the server to be running. All 36 API tests validate CRUD operations, automations, and special endpoints.

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
