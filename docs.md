# NIDS Workspace Documentation

## Architecture Overview

The NIDS workspace is a single-page application (SPA) with a Node.js/Express backend serving a REST API and static frontend files. Authentication uses JWT tokens with HTTP-only cookies. Data is stored in JSON files on disk.

```
Browser ──HTTP/HTTPS──> Express Server ──fs──> JSON files
                                │
                      ┌─────────┼─────────┐
                      │         │         │
                   tshark   PowerShell   Windows API
                   (PCAP)   (Monitor)    (Updates)
```

## Server (server.js)

The Express server listens on `http://localhost:3000` and optionally `https://localhost:3443`. It provides:

- **Static file serving** from `public/`
- **REST CRUD** for all data tables
- **Automations engine** with event hooks on create/update
- **Authentication** via JWT (Bearer token + HTTP-only cookie)
- **PCAP analysis** via tshark wrapper
- **Host monitoring** via PowerShell
- **Patch management** via PowerShell/Windows Update API

### Key Server Configuration (lib/config.js)

| Setting | Default | Description |
|---------|---------|-------------|
| `port` | 3000 | HTTP port |
| `https.port` | 3443 | HTTPS port |
| `https.enabled` | false | Enable HTTPS |
| `jwtSecret` | auto | JWT signing secret |
| `jwtExpiresIn` | 8h | Token expiry |
| `cookieName` | nids_token | Auth cookie name |
| `cookieMaxAge` | 28800000 | Cookie TTL (8h) |
| `defaultPageSize` | 50 | Pagination default |
| `maxPageSize` | 500 | Max page size |

## Authentication

### System
- JWT-based authentication with HTTP-only cookies (primary) and Bearer token fallback
- Login at `POST /api/auth/login` with `{ username, password }`
- Default credentials: `admin` / `admin`
- Cookie is set with `httpOnly: true, sameSite: 'lax'` for CSRF protection
- Session expires after 8 hours of inactivity

### Frontend
- `public/app.js` provides `apiFetch()` which includes credentials via `credentials: 'include'`
- On 401 response, redirects to `/login`
- Login page stores user info in `localStorage` (not the token — that's in the cookie)

## Data Layer

### Storage
All data is stored as JSON arrays in `data/`:
- `incidents.json` — Security incidents and alerts
- `detection-rules.json` — Detection rule definitions
- `threat-intel.json` — Threat intelligence/IOC data
- `engineering-tasks.json` — Engineering task board
- `network-assets.json` — Network device inventory
- `network-traffic.json` — Traffic flow records
- `qa-tests.json` — QA test cases
- `automations-log.json` — Automation event history
- `pcap-captures.json` — PCAP capture metadata
- `pcap/` — Directory for uploaded PCAP files

### CRUD API
Generic CRUD endpoints at `/api/:table` with automatic `id` assignment, pagination (`_page`, `_limit` query params), and search (`_search` param). Responses include `Link` headers for pagination.

## PCAP Analysis (lib/pcap.js)

### Dependencies
- **tshark** (Wireshark CLI) version 4.6.6+ at `C:\Program Files\Wireshark\tshark.exe`
- **Npcap** for live capture (must be installed manually as administrator)
- **multer** npm package for file uploads

### Features

#### PCAP File Management
- Upload PCAP/PCAPNG files via `POST /api/pcap/upload`
- List, view, and delete uploaded captures
- Files stored in `data/pcap/` with metadata in `data/pcap-captures.json`

#### Protocol Hierarchy
`GET /api/pcap/captures/:id/analysis/protocols`
- Uses `tshark -T fields -z io,phs` to extract protocol tree
- Returns protocol name, packet count, byte count, and percentage

#### Endpoints
`GET /api/pcap/captures/:id/analysis/endpoints`
- Uses `tshark -T fields -z endpoints,<type>` for IPv4, IPv6, TCP, UDP, Ethernet
- Returns address, packet count, byte count per endpoint

#### Conversations
`GET /api/pcap/captures/:id/analysis/conversations`
- Uses `tshark -T fields -z conv,<type>` for IPv4, TCP, UDP, Ethernet
- Returns conversation pairs with traffic statistics

#### Packet Listing
`GET /api/pcap/captures/:id/analysis/packets?page=1&limit=50&filter=`
- Uses `tshark -T json -Y <filter> -T fields -e <fields>` for packet-level data
- Extracted fields: frame number, time, source/dest IP, ports, protocol, length, info
- Optional Wireshark display filter via `?filter=`
- Paginated with `page` and `limit` query params

#### Display Filter Validation
`POST /api/pcap/validate-filter`
- Validates Wireshark display filter syntax using `tshark -Y <filter> -r <file>`
- Returns `{ valid: true }` or `{ valid: false, error: "..." }`
- Also validates via regex for common patterns without a PCAP file

#### PCAP Export
`GET /api/pcap/captures/:id/export`
- Streams the original PCAP file for download

#### Live Capture
`POST /api/capture/start`, `POST /api/capture/stop`
- Starts/stops tshark live capture on specified interface
- Uses `tshark -i <interface> -w <file> -a duration:<seconds>` for timed capture
- Captures saved to `data/pcap/` and metadata recorded
- Requires Npcap (admin install) on Windows

### tshark Commands Reference

| Command | Output Format | Purpose |
|---------|--------------|---------|
| `tshark -r file -T fields -z io,phs` | Text table | Protocol hierarchy |
| `tshark -r file -T fields -z endpoints,ip` | Text table | Endpoint stats |
| `tshark -r file -T fields -z conv,tcp` | Text table | Conversation stats |
| `tshark -r file -T json -Y "filter" -e frame.number -e ...` | JSON array | Packet listing |
| `tshark -i eth0 -w file.pcap -a duration:30` | PCAP file | Live capture |
| `tshark -r file -Y "filter"` | Exit code | Filter validation |

## Host Monitoring (lib/monitor.js)

### Architecture
Uses PowerShell cmdlets executed via `child_process.execSync` with UTF-8 output encoding. All commands run in-process (synchronous) for simplicity. Some commands require administrator privileges.

### Endpoints

#### Active Connections
`GET /api/monitor/connections`
```
PowerShell: Get-NetTCPConnection | Select ... & Get-NetUDPEndpoint | Select ...
```
Returns all TCP/UDP connections with:
- Local/remote address and port
- Connection state (TCP)
- Owning process ID, process name, and path
- `?filter=` query param for text search across all fields

#### Listening Ports
`GET /api/monitor/ports`
```
PowerShell: Get-NetTCPConnection -State Listen | Select ...
```
Returns listening ports with:
- Port number, protocol
- Process name, PID, path
- User account (via Get-Process -IncludeUserName)

#### Process Details
`GET /api/monitor/process/:pid`
```
PowerShell: Get-Process -Id <pid> | Select ...
```
Returns detailed process information:
- Name, PID, CPU time, memory (working set, private, virtual)
- Thread count, handle count
- Command line, start time, user

#### Network Interfaces
`GET /api/monitor/interfaces`
```
PowerShell: Get-NetAdapter | Select ...
```
Returns network adapters with:
- Name, description, MAC address
- Link speed, status, admin status
- Interface index, type

#### System Info
`GET /api/monitor/system`
- Hostname, OS version, last boot
- CPU: model, cores, logical processors, load percentage
- Memory: total, available, used (GB), usage percentage
- Disks: drive letter, size, free space, usage percentage

#### Bandwidth
`GET /api/monitor/bandwidth`
```
PowerShell: Get-NetAdapterStatistics | Select ...
```
Returns per-interface bandwidth statistics:
- Received/sent bytes and packets
- Unicast and discard packet counts

#### ARP Table
`GET /api/monitor/arp`
```
PowerShell: arp -a
```
Returns ARP cache entries parsed from `arp -a` text output:
- IP address, MAC address, interface, type (dynamic/static)
- Note: Uses `arp -a` CLI instead of `Get-NetNeighbor` for broader compatibility

#### DNS Cache
`GET /api/monitor/dns-cache`
```
PowerShell: Get-DnsClientCache | Select ...
```
Returns DNS client cache entries with:
- Record name, type, data (IP), TTL
- Section (Answer/Additional)

#### Routing Table
`GET /api/monitor/routing-table`
```
PowerShell: Get-NetRoute -AddressFamily IPv4 | Select ...
```
Returns IPv4 routing table:
- Destination, prefix length, next hop
- Interface, metric, route policy

#### Network Scan
`POST /api/monitor/scan` with body: `{ subnet: "192.168.1" }`
Two-phase scan:
1. **ARP phase** (fast) — checks local ARP cache for subnet matches
2. **Ping sweep** (comprehensive) — parallel ICMP pings across `.1-.254`
Returns discovered hosts with IP, MAC (from ARP), hostname, and response time

## Patch Management (lib/patch.js)

### Architecture
Uses PowerShell for `Get-HotFix` listing and Windows Update API via `Microsoft.Update.Session` COM object for scanning/installing updates. Results are cached and audited.

### Endpoints

#### Installed Hotfixes
`GET /api/patch/hotfixes`
```
PowerShell: Get-HotFix | Select HotFixId, Description, InstalledOn, InstalledBy
```
Returns list of installed Windows updates:
- KB ID, description, install date, installer
- Supports `?filter=` search across all fields

#### Pending Updates
`GET /api/patch/updates`
```
PowerShell: (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(...)
```
Scans Windows Update API for pending updates:
- KB ID, title, description, severity, category
- Support URL, update type (Important/Optional)
- Results are cached for 5 minutes to avoid repeated scans

#### Install Update
`POST /api/patch/install` with body: `{ kbId: "KB5000000" }`
```
PowerShell: (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(...).Updates | Where { $_.Title -match $kbId }
```
- Searches for the specific KB
- Creates a downloader and installer collection
- Returns download/install progress percentage
- Requires administrator privileges

#### Audit Log
`GET /api/patch/log`
Returns audit log of all patch operations with:
- Timestamp, action (scan/list/install)
- KB ID, status (success/error), details message

### Important Notes
- Windows Update API requires the Windows Update service to be running
- Install operations require administrator privileges
- Some PowerShell commands may timeout (45-second default)

## Frontend Pages

### Common Infrastructure
- **Dark SOC theme** defined in `public/styles.css`
- **Shared utilities** in `public/app.js`: `apiFetch`, `showToast`, `showModal`, `showLoading`, `hideLoading`
- **Server-Sent Events** (SSE) connection for real-time dashboard updates
- **Sidebar navigation** with links organized by category
- All pages include cookie-based authentication via `apiFetch` with `credentials: 'include'`

### Dashboard (`/`)
- Aggregate incident stats (total, critical, resolved, avg CVSS)
- Severity distribution bar chart
- Status breakdown pie chart
- Attack-type bar chart
- Recent incidents table
- Real-time updates via SSE

### Incidents (`/incidents`)
- Filterable board grouped by severity
- Detail modal with full incident data
- Search across title, source IP, assignee
- Create/update/delete operations
- Automation hooks on critical severity and resolution

### Detection Rules (`/rules`)
- Grouped by status (Active, In Development, Deprecated)
- Linked to engineering tasks
- Priority and false-positive rate display

### Threat Intelligence (`/threat-intel`)
- CVE and IOC tracking
- Risk scoring and status management
- Search and filter capabilities

### Engineering Tasks (`/tasks`)
- Sprint-based task board with Kanban-style layout
- Assignee and sprint filtering
- Rule linking for CI/CD promotion automation

### Assets (`/assets`)
- Network device inventory
- Risk levels, health status, grouping
- Add/delete functionality

### Network Monitoring (`/network-monitoring`)
- Real-time traffic flow viewer with Chart.js visualizations
- Protocol distribution (pie chart)
- Traffic over time (line chart)
- Wireshark display filter bar with syntax validation
- "Open in Wireshark" — copies display filter to clipboard
- "Export CSV" — downloads filtered flows as CSV
- ToD (Time of Day) heatmap

### PCAP Analysis (`/pcap-analysis`)
- PCAP file upload with drag-and-drop
- Capture list with metadata (file, size, packets, date)
- Protocol hierarchy tree view with packet/byte counts
- Endpoint statistics (IPv4, IPv6, TCP, UDP, Ethernet)
- Conversation analysis with traffic stats
- Packet browser with:
  - Wireshark display filter input with live validation
  - Paginated packet table (frame number, time, IPs, ports, protocol, length, info)
  - Raw PCAP file download

### Host Monitoring (`/host-monitoring`)
- System info header (hostname, uptime, CPU, memory usage)
- Four tabbed views:
  1. **Active Connections** — TCP/UDP connections with process details; filterable by text search
  2. **Open Ports** — Listening ports with process info; kill process button, process detail modal
  3. **Bandwidth** — Interface cards with bandwidth stats (sent/received bytes, packets)
  4. **Network Discovery** — ARP table, routing table, subnet scanner with auto-detect and results display

### Patch Management (`/patch-management`)
- Two-tab layout:
  1. **Installed Hotfixes** — Filterable table of installed Windows updates with KB IDs
  2. **Pending Updates** — Scan results from Windows Update API with install buttons
- Upgrade to admin mode prompt for Windows Update operations
- Audit log for tracking patch activity

### QA Tests (`/qa`)
- Test case management with CI/CD promotion
- Filter by rule association, status, priority

### Customer Report (`/customer-report`)
- Client-ready resolved incidents view
- CVSS scores, resolution times, attack type breakdowns

## Display Filter Syntax

### Supported on `/api/network-traffic`
The server implements a token-based display filter evaluator for the network traffic endpoint. Supports:

| Operator | Example | Description |
|----------|---------|-------------|
| `==` | `protocol == HTTP` | Equality |
| `!=` | `status != allowed` | Inequality |
| `>` | `bytes > 1000` | Greater than |
| `<` | `bytes < 500` | Less than |
| `>=` | `bytes >= 1000` | Greater or equal |
| `<=` | `bytes <= 500` | Less or equal |
| `contains` | `srcIp contains 10.0` | Substring match |
| `matches` | `destIp matches /^192\.168/` | Regex match |
| `&&` / `and` | `protocol == HTTP && bytes > 1000` | AND |
| `\|\|` / `or` | `status == suspicious \|\| status == blocked` | OR |
| `!` / `not` | `!protocol == DNS` | NOT |
| `( )` | `(protocol == HTTP \|\| protocol == HTTPS) && bytes > 500` | Grouping |

### Field Names (for traffic filter)
- `srcIp` — Source IP address
- `destIp` — Destination IP address
- `srcPort` — Source port (numeric)
- `destPort` — Destination port (numeric)
- `protocol` — Protocol name (string)
- `bytes` — Byte count (numeric)
- `packets` — Packet count (numeric)
- `duration` — Flow duration (numeric)
- `status` — allowed/blocked/suspicious
- `application` — Application label
- `country` — Geo-location code
- `timestamp` — ISO date string

### PCAP Display Filter (tshark native)
The PCAP analysis page passes filters directly to tshark's `-Y` flag, supporting full Wireshark display filter syntax:
- `ip.src == 192.168.1.1`
- `tcp.port == 443`
- `http.request`
- `frame.number >= 100 && frame.number <= 200`

## Styling Reference (public/styles.css)

### PCAP Analysis Styles
- `.pcap-upload-area` — Drag-and-drop upload zone
- `.protocol-tree` — Indented protocol hierarchy
- `.wireshark-filter` — Wireshark-style display filter input with colored validation indicator
- `.hex-dump` — Monospace hex/ASCII packet dump
- `.capture-indicator` — Green pulsing dot for active capture
- `.pcap-table` — Packet listing table with fixed layout

### Tab Navigation
- `.tab-nav` / `.tab-btn` — Tab bar for multi-tab pages
- `.tab-content` / `.tab-pane` — Tab content containers
- Active tab styled with `.tab-btn.active`

### Disabled State
- `.disabled-btn` — Grayed-out button for unavailable features
- Used for live capture when Npcap unavailable

## Troubleshooting

### PCAP / tshark Issues
| Problem | Solution |
|---------|----------|
| "tshark not found" | Install Wireshark (includes tshark CLI) |
| "Npcap not installed" | Run `npcap-installer.exe` as Administrator |
| Live capture fails | Check Npcap installation, run PowerShell as Admin |
| Filter validation fails | Ensure file path has no spaces; tshark 4.x required |
| Upload fails | Check `data/pcap/` directory exists and is writable |

### Host Monitoring Issues
| Problem | Solution |
|---------|----------|
| Empty connections/ports | Run PowerShell as Administrator |
| ARP table empty | Check network connectivity |
| Scan returns no hosts | Check subnet value; Windows firewall may block ICMP |
| Process details fail | Process may have exited; run as Admin |
| PowerShell timeout | Large output sets may need increased timeout in monitor.js |

### Patch Management Issues
| Problem | Solution |
|---------|----------|
| Get-HotFix returns nothing | Run as Administrator; check `systeminfo` works |
| Pending updates empty | Ensure Windows Update service is running (`Get-Service wuauserv`) |
| Install fails | Run server as Administrator; check KB ID is correct |
| COM error | Windows Update API requires Windows 8+ / Server 2012+ |

### Authentication Issues
| Problem | Solution |
|---------|----------|
| 401 errors after login | Clear cookies and localStorage, re-login |
| Infinite redirect loop | Check that `credentials: 'include'` is in fetch options |
| Cookie not set | Browser may block third-party cookies; use same-origin |

## Development

### Adding a New Data Table
1. Create `data/<table>.json` with `[]`
2. CRUD is automatic via the generic route handler
3. Add specific endpoints in `server.js` if needed
4. Create frontend page with `apiFetch` for API calls

### Testing
```bash
npm test
```
Runs `node test-api.js` which validates all CRUD operations, automations, and special endpoints. Server must be running.

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | HTTP port |
| `HTTPS_ENABLED` | false | Enable HTTPS |
| `HTTPS_PORT` | 3443 | HTTPS port |
| `CORS_ORIGIN` | * | CORS allowed origin |
| `JWT_SECRET` | auto | JWT signing secret |
| `DEFAULT_PAGE_SIZE` | 50 | Default page size |
| `MAX_PAGE_SIZE` | 500 | Maximum page size |
