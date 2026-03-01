# AWS VPC Flow Logs Visualizer (Django DRF + React)

This starter implements a full-stack baseline for your use case:

- ingest AWS VPC flow logs
- correlate `client->server (c2s)` and `server->client (s2c)` directions
- enrich IPs with metadata (name, provider/team, tags, attributes)
- group IPs into CIDR-based VPC/container/external network groups
- visualize provider/consumer relationships as a bubble mesh graph
- generate firewall rule suggestions from observed traffic

## Table of Contents

- [Project Layout](#project-layout)
- [Screenshots \& Demo](#screenshots--demo)
- [Backend Setup](#backend-setup)
- [Frontend Setup](#frontend-setup)
- [Container (Docker)](#container-docker)
- [GitHub Container Registry (GHCR)](#github-container-registry-ghcr)
- [Core API Endpoints](#core-api-endpoints)
- [Example Upload Request](#example-upload-request)
- [Notes](#notes)

## Project Layout

- `backend/` Django + DRF API
- `frontend/` React (Vite) UI

## Screenshots & Demo

- Demo video: [Streamable walkthrough](https://streamable.com/26qh7e)

<table>
  <tr>
    <td align="center">
      <b>Dashboard</b><br />
      <a href="docs/images/image_dash.png">
        <img src="docs/images/image_dash.png" alt="Dashboard" width="420" />
      </a>
    </td>
    <td align="center">
      <b>Map View</b><br />
      <a href="docs/images/image_map.png">
        <img src="docs/images/image_map.png" alt="Map view" width="420" />
      </a>
    </td>
  </tr>
  <tr>
    <td align="center">
      <b>Flow Logs</b><br />
      <a href="docs/images/image_flowlogs.png">
        <img src="docs/images/image_flowlogs.png" alt="Flow logs" width="420" />
      </a>
    </td>
    <td align="center">
      <b>Assets</b><br />
      <a href="docs/images/image_assets.png">
        <img src="docs/images/image_assets.png" alt="Assets" width="420" />
      </a>
    </td>
  </tr>
  <tr>
    <td align="center" colspan="2">
      <b>Firewall Simulator</b><br />
      <a href="docs/images/image_firewal_sim.png">
        <img src="docs/images/image_firewal_sim.png" alt="Firewall simulator" width="520" />
      </a>
    </td>
  </tr>
</table>

## Backend Setup

```bash
cd backend
poetry install
poetry run python manage.py migrate
poetry run python manage.py runserver
```

Backend runs on `http://localhost:8000`.

Seed realistic demo data (assets/groups/flows/correlations + firewall simulator snapshots):

```bash
./scripts/seed_demo_data.sh
```

Equivalent direct command:

```bash
cd backend && poetry run python manage.py seed_demo_data --reset --source demo-seed --seed 20260301 --days 14 --flow-pairs 2200
```

Database behavior:

- default is SQLite (`backend/db.sqlite3`)
- set `DJANGO_DATABASE_URL` (or `DATABASE_URL`) to use PostgreSQL, for example:
  `postgresql://user:password@localhost:5432/aws_vpc_flow_logs`
- for local Poetry runs with PostgreSQL, install driver once:
  `cd backend && poetry add "psycopg[binary]"`

Optional API login:

- leave unset for open access (current default behavior)
- set `WRITE_ACCOUNT=username:password` for read/write access
- set `READ_ACCOUNT=username:password` for read-only access
- when either variable is set, API endpoints require HTTP Basic auth

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:5173` and proxies `/api` to the Django backend.

## Container (Docker)

Build and run the full app (frontend + backend) as one container:

```bash
docker build -t aws-vpc-flow-logs-visualizer:local .
docker run --rm -p 8000:8000 aws-vpc-flow-logs-visualizer:local
```

Use PostgreSQL in container runtime by passing a DB URL:

```bash
docker run --rm -p 8000:8000 \
  -e DJANGO_DATABASE_URL='postgresql://user:password@host:5432/aws_vpc_flow_logs' \
  aws-vpc-flow-logs-visualizer:local
```

Enable optional auth in container runtime:

```bash
docker run --rm -p 8000:8000 \
  -e WRITE_ACCOUNT='admin:admin' \
  -e READ_ACCOUNT='user:user' \
  aws-vpc-flow-logs-visualizer:local
```

Then open:

- `http://localhost:8000/` (React app)
- `http://localhost:8000/api/docs/` (Swagger UI)
- `http://localhost:8000/api/redoc/` (ReDoc)

You can also run with Docker Compose:

```bash
docker compose up --build
```

## GitHub Container Registry (GHCR)

This repo includes `.github/workflows/container.yml`, which builds and publishes:

- `ghcr.io/jbhoorasingh/aws-vpc-flow-logs-visualizer:latest` on pushes to `main`
- `ghcr.io/jbhoorasingh/aws-vpc-flow-logs-visualizer:v*` when you push a version tag
- `ghcr.io/jbhoorasingh/aws-vpc-flow-logs-visualizer:sha-...` for immutable deploys

Single-line deploy from GHCR:

```bash
docker run -d --name aws-vpc-flow-logs-visualizer --restart unless-stopped -p 8000:8000 ghcr.io/jbhoorasingh/aws-vpc-flow-logs-visualizer:latest
```

## Core API Endpoints

- `GET /api/health/`
- `GET /api/search/?q=<term>` (global search across flows/assets/groups)
- `POST /api/uploads/flow-logs/`
  - accepts multipart `file`, repeated `files` (bulk), or text `lines`
  - file supports plain text flow logs and gzip-compressed `.log.gz`
  - optional: `source`, `auto_correlate=true|false`
- `POST /api/correlation/rebuild/`
- `GET /api/flow-logs/`
  - optional advanced expression filter with `advanced_filter`, e.g.
    `((addr.src == 10.108.1.1) or (addr.dst == 10.108.1.1)) and (protocol == icmp) and (port.dst == 80)`
  - supports asset metadata fields like `instance.owner=4442424324`, `instance.name=*aws*`, `instance.region=us-east-1`, `instance.az=us-east-1d`, and `instance.tags.environment="prod"` (`asset.*` is an alias)
- `GET /api/correlated-flows/`
- `GET/POST /api/ip-metadata/`
- `POST /api/metadata/import/`
- `GET/POST /api/network-groups/`
- `POST /api/maintenance/network-groups/import/`
- `GET /api/mesh/`
- `GET /api/firewall/recommendations/?min_bytes=0`
- `GET /api/schema/` (OpenAPI schema)
- `GET /api/docs/` (Swagger UI)
- `GET /api/redoc/` (ReDoc)

Network groups support either a single `cidr` or a `cidrs` list:

```json
{
  "name": "prod-vpc",
  "kind": "VPC",
  "cidrs": ["10.0.0.0/16", "10.1.0.0/16"]
}
```

## Example Upload Request

```bash
curl -X POST http://localhost:8000/api/uploads/flow-logs/ \
  -F "source=prod-vpc" \
  -F "auto_correlate=true" \
  -F "file=@sample-flow.log"
```

## Notes

- Correlation uses server-port inference heuristics to pair c2s/s2c conversations.
- Firewall recommendations aggregate by CIDR group when available; otherwise by host CIDR.
- Service mesh view uses Cytoscape.js with interactive zoom/pan, layout switching, and node/edge inspection.
- SQLite is configured by default for fast local iteration.
