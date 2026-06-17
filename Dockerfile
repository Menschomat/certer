# Stage 1: Build static Go binary natively for target platforms
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# TARGETOS and TARGETARCH automatically populated by buildx
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s" -o bin/server cmd/server/main.go

# Stage 2: Scratch minimal execution image
FROM scratch

# Copy CA Certificates for ACME TLS handshakes
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy statically compiled server binary
COPY --from=builder /app/bin/server /server

EXPOSE 8080
EXPOSE 5002

ENTRYPOINT ["/server"]
