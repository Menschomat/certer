# Terraform Provider for Cert-Central

The Cert-Central Terraform provider allows you to manage SSL/TLS certificate configurations, provision access keys, and fetch issued certificates directly within your Terraform workflows.

---

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) 1.0+
- [Go](https://golang.org) 1.22+ (for building the provider)

---

## Provider Configuration & Private Registries

Since you do not need a `terraform.io` account, you can use the provider through either a **Gitea Private Registry** or a **Local Plugin Directory**.

### Option A: Gitea Package Registry (Recommended)
Gitea has a built-in, Terraform-compliant package registry. When you write:
```hcl
terraform {
  required_providers {
    certcentral = {
      source  = "gitea.dmz.k8s.menscho.space/m0space/certcentral"
      version = "~> 1.0.0"
    }
  }
}
```
Terraform resolves this by contacting `gitea.dmz.k8s.menscho.space` to download the pre-compiled binary matching your platform (e.g., `linux_amd64` or `darwin_arm64`). It does not read your Git repository or subdirectories directly.

To publish your compiled provider to Gitea's registry:
1. Compile and zip the provider binary:
   ```bash
   cd terraform-provider-certcentral
   go build -o terraform-provider-certcentral
   zip terraform-provider-certcentral_1.0.0_darwin_arm64.zip terraform-provider-certcentral
   ```
2. Upload it to your Gitea instance using `curl` (replace `YOUR_TOKEN` with a Gitea personal access token):
   ```bash
   curl --header "Authorization: token YOUR_TOKEN" \
        --upload-file terraform-provider-certcentral_1.0.0_darwin_arm64.zip \
        https://gitea.dmz.k8s.menscho.space/api/packages/m0space/terraform-provider/certcentral/1.0.0/darwin_arm64.zip
   ```

*Note: Gitea automatically handles Terraform service discovery under the hood at your domain's `.well-known/terraform.json` endpoint.*

### Option B: Local Plugin Installation
For offline use or local development, you can compile the provider and place it directly into your local Terraform plugin directory:

1. Build and copy the binary to your local plugin mirror directory (adjusting architecture name as needed):
   ```bash
   cd terraform-provider-certcentral
   go build -o terraform-provider-certcentral
   
   # For macOS (Apple Silicon):
   mkdir -p ~/.terraform.d/plugins/gitea.dmz.k8s.menscho.space/m0space/certcentral/1.0.0/darwin_arm64/
   cp terraform-provider-certcentral ~/.terraform.d/plugins/gitea.dmz.k8s.menscho.space/m0space/certcentral/1.0.0/darwin_arm64/terraform-provider-certcentral_v1.0.0
   ```

2. Reference your local source in your Terraform configuration:
   ```hcl
   terraform {
     required_providers {
       certcentral = {
         source  = "gitea.dmz.k8s.menscho.space/m0space/certcentral"
         version = "1.0.0"
       }
     }
   }
   ```
   When running `terraform init`, it will resolve the provider directly from your local cache directory.

For either option, you must configure the provider block with your `cert-central` endpoint and admin API key:

```hcl
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
