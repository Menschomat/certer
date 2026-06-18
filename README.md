# Cert Central

Production-grade, automated SSL/TLS certificate management service in Go. Integrates with Let's Encrypt (ACME v2) using DNS-01 challenges, schedules renewals, and exposes certificates via a domain-restricted, authenticated REST API.

---

## Architecture

```mermaid
graph TD
    subgraph Config
        JSON[config.json]
        Env[Environment Variables]
    end

    subgraph Service["Bootstrap (Main Startup)"]
        Startup[Main Bootstrapper]
        JSON --> Startup
        Env --> Startup
    end

    subgraph BackgroundWorker["Background Worker"]
        Sched[cert.Scheduler] -->|Examine Expiry / Config Changes| Issuer[cert.Issuer]
        Issuer -->|DNS-01 / HTTP-01 Challenge| ACME[ACME CA Server]
    end

    subgraph WebServer["API Web Server"]
        API[api.Server] -->|GET /api/v1/certificates| Auth{Argon2id Auth}
        Auth -->|Authorized| Filter[Filter & Return Certificates]
    end

    subgraph Storage["Certificate Storage"]
        Certs[./certs/*.crt, *.key]
    end

    Startup -->|Spawns| Sched
    Startup -->|Starts| API
    
    ACME -->|Writes PEMs| Certs
    Filter -->|Reads PEMs| Certs
```

---

## Features

- **DNS-01 Challenges**: Issue wildcard and SAN certificates using Cloudflare or Hetzner DNS providers.
- **Background Scheduler**: Periodically monitors local certificate expiration dates and domain configurations, triggering renewals only when needed.
- **Argon2id Token Authentication**: Protects the HTTP API using API keys hashed with the Argon2id key derivation function.
- **Domain-Restricted Access Control**: Restricts authenticated tokens to retrieving only specified domains.
- **Zero-Downtime Design**: Background worker handles renewals seamlessly without interrupting the web server.

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
  "certificates": [
    {
      "primary": "example.com",
      "sans": ["*.example.com", "www.example.com"]
    }
  ],
  "api_keys": [
    {
      "token": "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs",
      "allowed_domains": ["example.com"]
    }
  ]
}
```

#### Configuration Options

| Field | Type | Default | Env Var | Description |
|---|---|---|---|---|
| `port` | string | `"8080"` | `PORT` | Port for the HTTP API server |
| `env` | string | `"development"` | `ENV` | Service environment (`development` or `production`) |
| `acme_provider` | string | `"letsencrypt"` | `ACME_PROVIDER` | ACME provider (`letsencrypt` or `zerossl`) |
| `acme_directory_url` | string | *(dynamic)* | `ACME_DIRECTORY_URL` | Directory URL of the ACME CA server |
| `acme_email` | string | *None* | `ACME_EMAIL` | Email address registered with the ACME provider |
| `eab_kid` | string | *None* | `EAB_KID` | Key ID for External Account Binding (EAB) |
| `eab_hmac` | string | *None* | `EAB_HMAC` | HMAC key for External Account Binding (EAB) |
| `cert_storage_dir` | string | `"./certs"` | `CERT_STORAGE_DIR` | Directory where certificates and keys are persisted |
| `challenge_port` | string | `"5002"` | `CHALLENGE_PORT` | HTTP port for the HTTP-01 challenge solver |
| `dns_provider` | string | *None* | `DNS_PROVIDER` | DNS provider (`cloudflare`, `hetzner`, or blank for HTTP-01 fallback) |
| `dns_resolvers` | list | *None* | `DNS_RESOLVERS` | DNS resolvers (comma-separated list) to verify DNS-01 propagation |
| `renew_threshold_days` | int | `30` | `RENEW_THRESHOLD_DAYS` | Days before expiry to trigger automatic renewal |
| `check_interval_hours` | int | `24` | `CHECK_INTERVAL_HOURS` | Hours between checking local certificate status |
| `certificates` | list | *None* | *None* | Target certificates (primary domain and SANs) |
| `api_keys` | list | *None* | *None* | Authorized API keys (Argon2id hashes) and allowed domains |

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
# Choose challenge solver: cloudflare, hetzner, or leave blank to fall back to HTTP-01
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
docker run --rm -it --entrypoint /keygen cert-central

# Generate Argon2id hash for a custom token
docker run --rm -it --entrypoint /keygen cert-central -token mysecret
```


---

## API Documentation

### 1. Health Status
Check if application is healthy.
- **Endpoint**: `GET /health`
- **Auth**: None
- **Response**:
  ```json
  {"status": "up"}
  ```

### 2. Fetch Certificates
Retrieve PEM-encoded certificates and private keys.
- **Endpoint**: `GET /api/v1/certificates`
- **Auth**: `Authorization: Bearer <TOKEN>` (or raw `<TOKEN>` in header)
- **Response**:
  ```json
  [
    {
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
docker build -t cert-central .
```

Run container:
```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config.json:/config.json \
  -v $(pwd)/certs:/certs \
  -e CF_DNS_API_TOKEN="your_token" \
  cert-central
```
