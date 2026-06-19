# Terraform Provider for Cert-Central

The Cert-Central Terraform provider allows you to manage SSL/TLS certificate configurations, provision access keys, and fetch issued certificates directly within your Terraform workflows.

---

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) 1.0+
- [Go](https://golang.org) 1.22+ (for building the provider)

---

## Provider Configuration

To use the provider, configure it with the HTTP address of your `cert-central` daemon and an administrative token:

```hcl
terraform {
  required_providers {
    certcentral = {
      source = "registry.terraform.io/menscho/certcentral"
    }
  }
}

provider "certcentral" {
  address = "http://localhost:8080"
  token   = "your_admin_api_token"
}
```

---

## Resources

### 1. `certcentral_certificate`

Manages a certificate configuration in the background renewal scheduler. When created, `cert-central` automatically schedules DNS-01/HTTP-01 ACME challenges to issue the certificate.

```hcl
resource "certcentral_certificate" "example" {
  primary = "example.com"
  sans    = [
    "*.example.com",
    "www.example.com"
  ]
}
```

#### Argument Reference
* `primary` (String, Required) - The primary domain name for the certificate. Changing this triggers resource replacement.
* `sans` (List of String, Optional) - Subject Alternative Names (SANs) for the certificate.

---

### 2. `certcentral_api_key`

Manages client API keys and access scopes in `cert-central`. Standard API keys can be restricted to only fetch certificates for specific domains.

```hcl
resource "certcentral_api_key" "web_client" {
  token           = "$argon2id$v=19$m=65536,t=3,p=2$..." # Argon2id hash of the token
  allowed_domains = ["example.com"]
  admin           = false
}
```

#### Argument Reference
* `token` (String, Required) - The Argon2id hash of the API key token (acts as the unique identifier). Changing this triggers resource replacement.
* `allowed_domains` (List of String, Optional) - Domains this standard token is allowed to fetch certificates for.
* `admin` (Boolean, Required) - If `true`, this token has administrative rights to call the control plane endpoints and cannot be used to fetch raw certificate private keys.

---

## Data Sources

### `certcentral_certificate_data`

Retrieves PEM-encoded certificate chains and private keys once they are successfully issued by `cert-central`. You can pass these to load balancers, CDN, or file structures.

```hcl
data "certcentral_certificate_data" "example" {
  domain = certcentral_certificate.example.primary
}

# Example: Output the certificate body
output "certificate_pem" {
  value     = data.certcentral_certificate_data.example.certificate
  sensitive = true
}

# Example: Pass details to another resource (e.g. AWS ACM)
resource "aws_acm_certificate" "imported" {
  private_key       = data.certcentral_certificate_data.example.private_key
  certificate_body  = data.certcentral_certificate_data.example.certificate
}
```

#### Attribute Reference
* `domain` (String, Required) - The primary domain of the certificate to fetch.
* `sans` (List of String, Computed) - SANs associated with the certificate.
* `issued` (Boolean, Computed) - `true` if the certificate has been successfully issued.
* `certificate` (String, Computed, Sensitive) - The PEM-encoded certificate chain.
* `private_key` (String, Computed, Sensitive) - The PEM-encoded private key.
* `cert_filename` (String, Computed) - The filename of the certificate stored on the server.
* `key_filename` (String, Computed) - The filename of the private key stored on the server.

---

## Local Development & Testing

### 1. Build the Provider
To build the provider binary locally, run:

```bash
cd terraform-provider-certcentral
go build -o terraform-provider-certcentral
```

### 2. Run Tests
To run provider and client unit tests, execute:

```bash
go test -v ./...
```
