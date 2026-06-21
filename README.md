# Certer

Production-grade, automated SSL/TLS certificate management service in Go. Integrates with Let's Encrypt (ACME v2) using DNS-01 challenges, schedules renewals, and exposes certificates via a domain-restricted, authenticated REST API.

---

## Architecture

```mermaid
flowchart TB
    %% Styling definitions
    classDef actor fill:#ececff,stroke:#9370db,stroke-width:2px;
    classDef internal fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef external fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef storage fill:#efebe9,stroke:#5d4037,stroke-width:2px;
    classDef tool fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;

    %% Actors & External Entities
    subgraph Actors ["Actors & External Systems"]
        admin["👤 Admin (Infrastructure / SecOps)"]:::actor
        client["💻 App Client (Fetch TLS Certs)"]:::actor
        acme["🌐 ACME CA (Let's Encrypt / ZeroSSL)"]:::external
        dns["☁️ DNS Provider (Cloudflare / Hetzner)"]:::external
    end

    %% Certer System Boundary
    subgraph Certer ["Certer System Daemon"]
        %% Bootstrap
        boot["🚀 Main Bootstrapper"]:::internal
        
        %% API Server
        subgraph WebServer ["Web API Server"]
            api["🔌 api.Server<br>(HTTP:8080 / HTTPS:8443)"]:::internal
            auth["🔒 Argon2id Authenticator"]:::internal
            router["🛣️ Table-driven Mux"]:::internal
            filter["🔍 Certificate & Team Filter"]:::internal
        end

        %% Scheduler
        subgraph BackgroundWorker ["Background Worker"]
            sched["⏰ cert.Scheduler<br>(Renewal Engine)"]:::internal
            issuer["📜 cert.Issuer<br>(Lego ACME Wrapper)"]:::internal
        end

        %% Files / Storage
        subgraph Storage ["Persisted Storage"]
            config["📄 config.json"]:::storage
            certsDir["📁 certs/ directory<br>(*.crt, *.key)"]:::storage
        end
    end

    %% CLI Tools
    subgraph CLITools ["CLI Utilities (Container Native)"]
        keygen["🔑 keygen CLI<br>(Argon2id Hash Generator)"]:::tool
        audit["📊 audit CLI<br>(Local Audit Logger)"]:::tool
    end

    %% Connections - Startup
    config -->|1. Loaded by| boot
    boot -->|2. Spawns| sched
    boot -->|2. Starts| api

    %% Connections - Admin & Configuration
    admin -->|Manage Config / Keys / Teams| api
    admin -->|Generate API key hashes| keygen
    admin -->|Query current state / report| audit
    audit -->|Authed requests| api

    %% Connections - Client Fetch
    client -->|GET /api/v1/certificates| api
    api -->|Verify Token| auth
    auth -->|Map Route| router
    router -->|Apply Scope| filter
    filter -->|Read PEMs| certsDir

    %% Connections - Background Renewal
    sched -->|Check expiry / configs| issuer
    issuer -->|DNS-01 Challenge| dns
    issuer -->|Validate & Issue| acme
    acme -->|Write new PEMs| certsDir
```

---

## Features

- **DNS-01 Challenges**: Issue wildcard and SAN certificates using Cloudflare or Hetzner DNS providers.
- **Background Scheduler**: Periodically monitors local certificate expiration dates and domain configurations, triggering renewals only when needed.
- **Argon2id Token Authentication**: Protects the HTTP API using API keys hashed with the Argon2id key derivation function.
- **Domain-Restricted Access Control**: Restricts authenticated tokens to retrieving only specified domains.
- **Zero-Downtime Design**: Background worker handles renewals seamlessly without interrupting the web server.

---

## Terraform Provider

To manage configurations (certificates, teams, and API keys) declaratively, you can use the official [Certer Terraform Provider](https://github.com/Menschomat/terraform-provider-certer).

It is published on the Terraform Registry at [Menschomat/certer](https://registry.terraform.io/providers/Menschomat/certer/latest/docs).

Example usage:
```hcl
terraform {
  required_providers {
    certer = {
      source  = "Menschomat/certer"
      version = "~> 1.0"
    }
  }
}

provider "certer" {
  address = "http://localhost:8080"
  token   = "your_admin_api_token"
}

resource "certer_team" "dev" {
  name        = "dev-team"
  description = "Development team"
}

resource "certer_certificate" "wildcard" {
  primary = "example.com"
  team_id = certer_team.dev.id
  sans    = ["*.example.com"]
}
```

---

## Getting Started

### Prerequisites
- Go 1.22+
- Make (optional)

### Setup Configuration
Copy the template configuration file:
```bash
cp example.config.json config.json
```

```json
{
  "port": "8080",
  "env": "development",
  "acme_provider": "letsencrypt",
  "acme_directory_url": "",
  "acme_email": "admin@example.com",
  "eab_kid": "",
  "eab_hmac": "",
  "cert_storage_dir": "./certs",
  "challenge_port": "5002",
  "dns_provider": "cloudflare",
  "dns_resolvers": [
    "1.1.1.1:53",
    "8.8.8.8:53"
  ],
  "renew_threshold_days": 30,
  "check_interval_hours": 24,
  "teams": [
    {
      "id": "019035a1-7b00-7521-8280-60b6adbf47ea",
      "name": "Team A",
      "description": "Core infrastructure team"
    }
  ],
  "certificates": [
    {
      "id": "019035a1-7b00-7521-8280-60b6adbf47eb",
      "primary": "example.com",
      "sans": ["*.example.com", "www.example.com"],
      "team_id": "019035a1-7b00-7521-8280-60b6adbf47ea",
      "description": "Production wildcard certificate"
    }
  ],
  "api_keys": [
    {
      "id": "019035a1-7b00-7521-8280-60b6adbf47ec",
      "token": "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs",
      "description": "Example admin API key",
      "allowed_certificates": ["019035a1-7b00-7521-8280-60b6adbf47eb"],
      "allowed_teams": ["019035a1-7b00-7521-8280-60b6adbf47ea"],
      "admin": true
    }
  ]
}
```

#### Configuration Options

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `port` | string | `"8080"` | `PORT` | Port for the HTTP API server |
| `https_port` | string | `"8443"` | `HTTPS_PORT` | Port for the HTTPS API server |
| `ssl_cert_id` | string | *None* | *None* | Optional certificate configuration ID to use for serving HTTPS |
| `env` | string | `"development"` | `ENV` | Service environment (`development` or `production`) |
| `acme_provider` | string | `"letsencrypt"` | `ACME_PROVIDER` | ACME provider (`letsencrypt` or `zerossl`) |
| `acme_directory_url` | string | *(dynamic)* | `ACME_DIRECTORY_URL` | Directory URL of the ACME CA server |
| `acme_email` | string | *None* | `ACME_EMAIL` | Email address registered with the ACME provider |
| `eab_kid` | string | *None* | `EAB_KID` | Key ID for External Account Binding (EAB) |
| `eab_hmac` | string | *None* | `EAB_HMAC` | HMAC key for External Account Binding (EAB) |
| `cert_storage_dir` | string | `"./certs"` | `CERT_STORAGE_DIR` | Directory where certificates and keys are persisted |
| `challenge_port` | string | `"5002"` | `CHALLENGE_PORT` | HTTP port for the HTTP-01 challenge solver |
| `dns_provider` | string | *None* | `DNS_PROVIDER` | DNS provider name (e.g. `cloudflare`, `hetzner`, `route53`, or any Lego-supported provider; blank for HTTP-01 fallback) |
| `dns_resolvers` | list | *None* | `DNS_RESOLVERS` | DNS resolvers (comma-separated list) to verify DNS-01 propagation |
| `renew_threshold_days` | int | `30` | `RENEW_THRESHOLD_DAYS` | Days before expiry to trigger automatic renewal |
| `check_interval_hours` | int | `24` | `CHECK_INTERVAL_HOURS` | Hours between checking local certificate status |
| `teams` | list | *None* | *None* | Target teams metadata list. Each object contains `id` (UUIDv7), `name` (string), and `description` (string) |
| `certificates` | list | *None* | *None* | Target certificates list. Each object contains `id` (UUIDv7), `primary` (domain name), `sans` (list of alternative domain names), `team_id` (UUIDv7 team identifier), and `description` (string) |
| `api_keys` | list | *None* | *None* | Authorized API keys list. Each object contains `id` (UUIDv7), `token` (Argon2id hash of the token), `description` (string), `allowed_certificates` (list of UUIDv7 certificate identifiers), `allowed_teams` (list of UUIDv7 team identifiers), and `admin` (boolean) |

### Dual HTTP & HTTPS Listeners

By default, `certer` boots and binds to both an HTTP port (`port`, defaults to `8080`) and an HTTPS port (`https_port`, defaults to `8443`) simultaneously.

To configure SSL/TLS for the HTTPS endpoint:
1. Provide a managed certificate configuration ID using `"ssl_cert_id"` inside `config.json`.
2. On boot, the server checks if the matching certificate and private key files (e.g. `certs/{ssl_cert_id}.crt` and `certs/{ssl_cert_id}.key`) exist.
3. If they exist, they are loaded to serve the HTTPS endpoint.
4. If they do not exist (or if `ssl_cert_id` is not configured), the server dynamically generates a temporary, self-signed P-256 ECDSA certificate in memory. This ensures the HTTPS endpoint remains up and functional immediately upon container startup.

### ACME Provider Configuration

#### 1. Let's Encrypt (Default)
By default, the service uses Let's Encrypt. The directory URL is automatically toggled depending on the `ENV` setting if `acme_directory_url` is omitted:
- **`ENV=development`** (or default): Defaults to Let's Encrypt Staging (`https://acme-staging-v02.api.letsencrypt.org/directory`).
- **`ENV=production`**: Defaults to Let's Encrypt Production (`https://acme-v02.api.letsencrypt.org/directory`).

#### 2. ZeroSSL
ZeroSSL can be configured in two ways:
- **Email-only Registration (Recommended):** Set `"acme_provider": "zerossl"` in your `config.json` (or environment variable `ACME_PROVIDER=zerossl`). The client will automatically contact ZeroSSL's API and generate/bind EAB credentials under the hood using your ACME email address.
- **Manual EAB Credentials:** If you prefer to bind to a pre-existing ZeroSSL developer account, provide your EAB credentials via configuration (`eab_kid` / `eab_hmac`) or environment variables (`EAB_KID` / `EAB_HMAC`).


### Environment Variables Configuration
Provide configuration parameters, custom resolvers, and API credentials for your DNS and ACME providers as environment variables:
```bash
# DNS Solver Configuration
# Choose challenge solver: cloudflare, hetzner, route53, or any Lego-supported provider (leave blank to fall back to HTTP-01).
# For the full list of 80+ supported providers and their required environment variables, see:
# https://go-acme.github.io/lego/dns/index.html
export DNS_PROVIDER="cloudflare"

# Optional comma-separated list of custom recursive DNS resolvers (e.g. to bypass local DNS caching or local resolution issues)
export DNS_RESOLVERS="1.1.1.1:53,8.8.8.8:53"

# Cloudflare DNS API Token (required if DNS_PROVIDER is cloudflare)
export CF_DNS_API_TOKEN="your_cloudflare_token"

# Or Hetzner DNS API Token (required if DNS_PROVIDER is hetzner)
export HETZNER_API_TOKEN="your_hetzner_api_token"

# EAB credentials for ZeroSSL (if applicable)
export EAB_KID="your_eab_key_id"
export EAB_HMAC="your_eab_hmac_key"
```

---

## Developer Commands

Run application:
```bash
make run
```

Build binaries:
```bash
make build
```

Run tests (100% mocked, TDD-verified):
```bash
make test
```

---

## Token Hashing Utility (CLI)
Hash custom tokens or generate secure random credentials using the built-in CLI wrapper:

#### 1. Running Locally
```bash
# Generate random secure token and its Argon2id hash
./hash.sh

# Generate Argon2id hash for a custom token
./hash.sh -token mysecret
```

#### 2. Running via Docker
Since the keygen utility is compiled and copied into the Docker image, you can invoke it by overriding the container entrypoint:
```bash
# Generate random secure token and its Argon2id hash
docker run --rm -it --entrypoint /keygen certer

# Generate Argon2id hash for a custom token
docker run --rm -it --entrypoint /keygen certer -token mysecret
```


---

## API Documentation

The REST API enforces a strict separation of duties based on token type:
- **Fetch Tokens (`admin = false`)**: Allowed to retrieve certificates via the read-only certificate endpoints. Forbidden from accessing configuration APIs.
- **Admin Tokens (`admin = true`)**: Allowed to manage configurations via `/api/v1/config/*` endpoints. Forbidden from reading actual certificate private keys.

All API requests (except `/health` and `/api/v1/hello`) must include the authentication token, typically passed as a `Bearer` token in the `Authorization` header:
```http
Authorization: Bearer <TOKEN>
```

---

### 1. Health Status
Check if the application is healthy.
- **Endpoint**: `GET /health`
- **Auth**: None
- **Response**:
  ```json
  {"status": "up"}
  ```

---

### 2. Hello Endpoint
Retrieve a greetings message.
- **Endpoint**: `GET /api/v1/hello`
- **Auth**: None
- **Response**:
  ```json
  {"message": "Hello from Certer!"}
  ```

---

### 3. Fetch Certificates
Retrieve PEM-encoded certificates and private keys.
- **Endpoint**: `GET /api/v1/certificates`
- **Auth**: Bearer Token (Fetch Token, `admin = false`)
- **Response**:
  ```json
  [
    {
      "id": "019035a1-7b00-7521-8280-60b6adbf47eb",
      "domain": "example.com",
      "sans": ["*.example.com", "www.example.com"],
      "issued": true,
      "certificate": "-----BEGIN CERTIFICATE-----\n...",
      "private_key": "-----BEGIN PRIVATE KEY-----\n...",
      "cert_filename": "example.com.crt",
      "key_filename": "example.com.key"
    }
  ]
  ```

---

### 4. Configuration: Certificates (Admin APIs)
Endpoints to manage target certificate configurations.
- **Auth**: Bearer Token (Admin Token, `admin = true`)

#### 4.1 Get All Configurations
- **Endpoint**: `GET /api/v1/config/certificates`
- **Response**:
  ```json
  [
    {
      "id": "019035a1-7b00-7521-8280-60b6adbf47eb",
      "primary": "example.com",
      "sans": ["*.example.com", "www.example.com"],
      "description": "Production wildcard certificate"
    }
  ]
  ```

#### 4.2 Create Configuration
Generates a new configuration and returns a generated UUID v7.
- **Endpoint**: `POST /api/v1/config/certificates`
- **Payload**:
  ```json
  {
    "primary": "new-domain.com",
    "sans": ["www.new-domain.com"],
    "description": "New website certificate"
  }
  ```
- **Response**:
  ```json
  {
    "id": "019035a1-f3b1-7a8e-a2cf-3847eab2038e",
    "primary": "new-domain.com",
    "sans": ["www.new-domain.com"],
    "description": "New website certificate"
  }
  ```

#### 4.3 Update Configuration
Updates an existing configuration by ID.
- **Endpoint**: `PUT /api/v1/config/certificates/{id}`
- **Payload**:
  ```json
  {
    "primary": "new-domain.com",
    "sans": ["www.new-domain.com", "api.new-domain.com"],
    "description": "Updated website certificate"
  }
  ```
- **Response**: Status `200 OK`

#### 4.4 Delete Configuration
Deletes certificate configuration and schedules cleanup of certificates on disk.
- **Endpoint**: `DELETE /api/v1/config/certificates/{id}`
- **Response**: Status `204 No Content`

---

### 5. Configuration: API Keys (Admin APIs)
Endpoints to manage API keys.
- **Auth**: Bearer Token (Admin Token, `admin = true`)

#### 5.1 Get All API Keys
Retrieves configured API keys (tokens are redacted).
- **Endpoint**: `GET /api/v1/config/api_keys`
- **Response**:
  ```json
  [
    {
      "id": "019035a1-7b00-7521-8280-60b6adbf47ec",
      "description": "Example admin API key",
      "allowed_certificates": ["019035a1-7b00-7521-8280-60b6adbf47eb"],
      "allowed_teams": ["019035a1-7b00-7521-8280-60b6adbf47ea"],
      "admin": true
    }
  ]
  ```

#### 5.2 Create API Key
Generates a new API key configuration and returns a generated UUID v7 and secure random token.
- **Endpoint**: `POST /api/v1/config/api_keys`
- **Payload**:
  ```json
  {
    "description": "Deploy Key for team B",
    "allowed_certificates": ["019035a1-7b00-7521-8280-60b6adbf47eb"],
    "allowed_teams": ["019035a1-7b00-7521-8280-60b6adbf47ea"],
    "admin": false
  }
  ```
- **Response**:
  ```json
  {
    "id": "019035a2-9eef-70a0-88cb-e8a0a9db4e21",
    "cleartext_token": "certc_9f02a...c0378",
    "description": "Deploy Key for team B",
    "allowed_certificates": ["019035a1-7b00-7521-8280-60b6adbf47eb"],
    "allowed_teams": ["019035a1-7b00-7521-8280-60b6adbf47ea"],
    "admin": false
  }
  ```

#### 5.3 Update API Key
Updates configuration of an API key by ID (e.g. allowed certificates/teams, admin role, or description).
- **Endpoint**: `PUT /api/v1/config/api_keys/{id}`
- **Payload**:
  ```json
  {
    "description": "Updated Deploy Key for team B",
    "allowed_certificates": ["019035a1-7b00-7521-8280-60b6adbf47eb"],
    "allowed_teams": ["019035a1-7b00-7521-8280-60b6adbf47ea"],
    "admin": false
  }
  ```
- **Response**: Status `200 OK`

#### 5.4 Delete API Key
- **Endpoint**: `DELETE /api/v1/config/api_keys/{id}`
- **Response**: Status `204 No Content`

---

### 6. Configuration: Teams (Admin APIs)
Endpoints to manage teams.
- **Auth**: Bearer Token (Admin Token, `admin = true`)

#### 6.1 Get All Teams
- **Endpoint**: `GET /api/v1/config/teams`
- **Response**:
  ```json
  [
    {
      "id": "019035a1-7b00-7521-8280-60b6adbf47ea",
      "name": "Team A",
      "description": "Core infrastructure team"
    }
  ]
  ```

#### 6.2 Create Team
Generates a new team configuration and returns a generated UUID v7.
- **Endpoint**: `POST /api/v1/config/teams`
- **Payload**:
  ```json
  {
    "name": "Team B",
    "description": "API Gateway team"
  }
  ```
- **Response**:
  ```json
  {
    "id": "019035a1-f3b1-7a8e-a2cf-3847eab2038e",
    "name": "Team B",
    "description": "API Gateway team"
  }
  ```

#### 6.3 Update Team
Updates an existing team configuration by ID.
- **Endpoint**: `PUT /api/v1/config/teams/{id}`
- **Payload**:
  ```json
  {
    "name": "Team B (Updated)",
    "description": "Edge routing and gateway team"
  }
  ```
- **Response**: Status `200 OK`

#### 6.4 Delete Team
Deletes a team configuration. Note that all certificates belonging to this team must have their `team_id` updated or be deleted to preserve referential integrity.
- **Endpoint**: `DELETE /api/v1/config/teams/{id}`
- **Response**: Status `204 No Content`

---

## Docker

### Docker Compose (Recommended)
You can configure and spin up the complete service using Docker Compose:

1. **Prepare configuration:**
   Ensure your `config.json` is set up in the root directory.
2. **Set up environment variables:**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and fill in your DNS provider and/or ZeroSSL EAB credentials.
3. **Start the service:**
   ```bash
   docker compose up -d --build
   ```
4. **Persisted Certs:**
   Certs and private keys will automatically be saved and persisted in the local `./certs` directory.

### Running with Docker CLI (Manual)
Build minimal Docker image from scratch:
```bash
docker build -t certer .
```

Run container:
```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config.json:/config.json \
  -v $(pwd)/certs:/certs \
  -e CF_DNS_API_TOKEN="your_token" \
  certer
```
