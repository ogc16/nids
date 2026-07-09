# nids-core

Network Intrusion Detection System - detection engine, traffic simulation, and security monitoring toolkit.

## Installation

### npm (public registry)

```bash
npm install nids-core
```

### GitHub Packages

Requires a GitHub token with `read:packages` scope.

**.npmrc**
```
@ogc16:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @ogc16/nids-core
```

## Usage

### Core Library (ESM)

```typescript
import { generatePacket, evaluatePacket, getRules } from "nids-core";

// Generate simulated network traffic
const packet = generatePacket();

// Evaluate packet against detection rules
const rules = getRules();
const alert = evaluatePacket(packet, rules);

// Access the traffic store
import { addPackets, getAlerts } from "nids-core/store";
addPackets([packet]);
console.log(getAlerts());
```

### Detection Engine

```typescript
import { processBatch, getInspectionMetrics } from "nids-core/engine";
import { loadBuiltinSignatures } from "nids-core/engine";

loadBuiltinSignatures();
const results = processBatch(packets, rules);
```

### Types

```typescript
import type { Packet, Alert, DetectionRule, TrafficStats } from "nids-core/types";
```

### React Components

```tsx
import { Card, Button, Badge, Select, StatusDot } from "nids-core/ui";
```

### Legacy Components

```tsx
import { Card, DataTable, Pagination } from "nids-core/components";
```

### Auth Utilities (Next.js)

```typescript
import { createToken, verifyToken, hashPassword } from "nids-core/auth";
```

### Zod Validation Schemas

```typescript
import { schemas, validate } from "nids-core/validate";
```

### In-Memory Store

```typescript
import { getTrafficStats, addAlerts } from "nids-core/store";
```

### Express Backend Server

```javascript
const app = require("nids-core/server");
app.listen(3000);
```

## Subpath Exports

| Path | Description |
|------|-------------|
| `nids-core` | Main entry (types + core modules) |
| `nids-core/types` | TypeScript type definitions |
| `nids-core/engine` | Detection engine, rules, inspector, protocol parser |
| `nids-core/traffic` | Network traffic simulation generator |
| `nids-core/store` | In-memory packet/alert ring buffer |
| `nids-core/assets` | Network asset management |
| `nids-core/auth` | JWT auth (Next.js) |
| `nids-core/validate` | Zod v4 validation schemas |
| `nids-core/export` | Client-side JSON/CSV download |
| `nids-core/siren` | Web Audio API siren |
| `nids-core/rate-limit` | In-memory rate limiter (Next.js) |
| `nids-core/csrf` | CSRF protection (Next.js) |
| `nids-core/errors` | API error handler (Next.js) |
| `nids-core/db` | SQLite database (better-sqlite3) |
| `nids-core/inspector` | Async concurrent packet inspector |
| `nids-core/ui` | React UI primitives (Tailwind-styled) |
| `nids-core/components` | Legacy React components |
| `nids-core/server` | Express.js backend app |
| `nids-core/routes` | Express route modules |

## Dependencies

- **jose**, **bcryptjs**, **zod**, **better-sqlite3** — runtime deps
- **next**, **react**, **react-dom** — optional peer deps (for Next.js/React modules)
