# Stage 1: Build static Go binary natively for target platforms
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# TARGETOS and TARGETARCH automatically populated by buildx
ARG TARGETOS
ARG TARGETARCH

RUN GOMEMLIMIT=1024MiB CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -p 1 -ldflags="-w -s" -o bin/server ./cmd/server && \
    GOMEMLIMIT=1024MiB CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -p 1 -ldflags="-w -s" -o bin/keygen ./cmd/keygen && \
    GOMEMLIMIT=1024MiB CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -p 1 -ldflags="-w -s" -o bin/audit ./cmd/audit

# Stage 2: Scratch minimal execution image
FROM scratch

# Copy CA Certificates for ACME TLS handshakes
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy statically compiled binaries
COPY --from=builder /app/bin/server /server
COPY --from=builder /app/bin/keygen /keygen
COPY --from=builder /app/bin/audit /audit

EXPOSE 8080
EXPOSE 5002

ENTRYPOINT ["/server"]
