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
- **Network Monitoring** — Real-time traffic flow viewer with protocol distribution charts, suspicious/blocked flow highlighting, and country-level detail

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

## Project Structure

```
nids/
├── server.js                 # Express API server with CRUD + automations
├── package.json
├── test-api.js               # API test suite (36 tests)
├── data/                     # JSON-backed data store
│   ├── incidents.json
│   ├── detection-rules.json
│   ├── threat-intel.json
│   ├── engineering-tasks.json
│   ├── network-assets.json
│   ├── network-traffic.json
│   ├── qa-tests.json
│   └── automations-log.json
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
| GET | `/api/automations/log` | Automation event history |
| POST | `/api/automations/trigger/severity-critical` | Fire critical alerts |
| POST | `/api/automations/trigger/resolved-asset-update` | Link resolved incidents to assets |

## Getting Started

### Prerequisites
- Node.js 18+]

### Install & Run
```bash
cd nids
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000)

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
