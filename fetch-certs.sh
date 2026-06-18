#!/usr/bin/env bash

set -euo pipefail

# Print usage details
usage() {
    echo "Usage: $0 <api_url> [destination_dir]"
    echo "Example: CERT_CENTRAL_TOKEN=\"your_token\" $0 http://localhost:8080/api/v1/certificates ./my-certs"
    exit 1
}

# 1. Validate environment token
if [ -z "${CERT_CENTRAL_TOKEN:-}" ]; then
    echo "Error: CERT_CENTRAL_TOKEN environment variable is not set." >&2
    usage
fi

# 2. Validate URL parameter
if [ $# -lt 1 ]; then
    echo "Error: Missing API URL parameter." >&2
    usage
fi

API_URL="$1"
DEST_DIR="${2:-.}"

# 3. Verify jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required to parse JSON responses but was not found in PATH." >&2
    exit 1
fi

# 4. Create destination directory
mkdir -p "$DEST_DIR"

echo "Fetching certificates from $API_URL..."

# 5. Retrieve JSON response from Cert Central
RESPONSE=$(curl -s -f -H "Authorization: Bearer $CERT_CENTRAL_TOKEN" "$API_URL")

if [ -z "$RESPONSE" ] || [ "$RESPONSE" == "[]" ]; then
    echo "No certificates returned or authorized for this token."
    exit 0
fi

# 6. Parse and write each certificate
echo "$RESPONSE" | jq -c '.[]' | while read -r cert_item; do
    domain=$(echo "$cert_item" | jq -r '.domain')
    issued=$(echo "$cert_item" | jq -r '.issued')
    cert_file=$(echo "$cert_item" | jq -r '.cert_filename')
    key_file=$(echo "$cert_item" | jq -r '.key_filename')
    
    if [ "$issued" = "true" ]; then
        echo " -> Saving certificate & key for: $domain (Files: $cert_file, $key_file)"
        
        echo "$cert_item" | jq -r '.certificate' > "$DEST_DIR/$cert_file"
        echo "$cert_item" | jq -r '.private_key' > "$DEST_DIR/$key_file"
        
        # Set secure permissions (read-write for owner only)
        chmod 600 "$DEST_DIR/$cert_file" "$DEST_DIR/$key_file"
    else
        echo " -> Skipping $domain: Not yet issued."
    fi
done

echo "Done! All available certificates saved to: $DEST_DIR"
