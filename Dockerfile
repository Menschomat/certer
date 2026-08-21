# Stage 1: Build static Go binary natively for target platforms
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

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
