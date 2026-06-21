.PHONY: run build test clean docker build-darwin-arm64 build-linux-amd64 build-linux-arm64 build-all docker-multi

# Run application
run:
	go run ./cmd/server

# Build application binary for host system
build:
	mkdir -p bin
	go build -o bin/server ./cmd/server
	go build -o bin/keygen ./cmd/keygen

# Cross compile for Mac Apple Silicon (M1/M2/M3/M4)
build-darwin-arm64:
	mkdir -p bin
	GOOS=darwin GOARCH=arm64 go build -o bin/server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build -o bin/keygen-darwin-arm64 ./cmd/keygen

# Cross compile for Linux AMD64 (Standard 64-bit Servers)
build-linux-amd64:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -o bin/server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -o bin/keygen-linux-amd64 ./cmd/keygen

# Cross compile for Linux ARM64 (AWS Graviton / ARM64 Servers)
build-linux-arm64:
	mkdir -p bin
	GOOS=linux GOARCH=arm64 go build -o bin/server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -o bin/keygen-linux-arm64 ./cmd/keygen

# Compile for all target platforms
build-all: build-darwin-arm64 build-linux-amd64 build-linux-arm64

# Run tests
test:
	go test -race -v ./...

# Build Docker image
docker:
	docker build -t certer .

# Build multi-platform Docker image using buildx (AMD64 & ARM64)
docker-multi:
	docker buildx build --platform linux/amd64,linux/arm64 -t certer:latest .

# Clean build artifacts
clean:
	rm -rf bin
