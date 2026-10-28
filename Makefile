.PHONY: all build test clean run deps help

BINARY_NAME=bomhound
BUILD_DIR=bin
OUTPUT_DIR=output

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) cmd/bomhound/main.go

test:
	@echo "Running tests..."
	go test -v -cover ./...

clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR) output-batch output-improved output-optimized

run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME)

deps:
	@echo "Downloading dependencies..."
	go mod tidy
	go mod download

GOPATH=$(shell go env GOPATH)

vulncheck:
	@echo "Running vulnerability check..."
	@command -v $(GOPATH)/bin/govulncheck >/dev/null 2>&1 || { \
		echo "Installing govulncheck..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	}
	$(GOPATH)/bin/govulncheck ./...

lint:
	@echo "Running linter..."
	@command -v $(GOPATH)/bin/golangci-lint >/dev/null 2>&1 || { \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	}
	$(GOPATH)/bin/golangci-lint run

help:
	@echo "Available targets:"
	@echo "  build       - Build the application"
	@echo "  test        - Run tests with coverage"
	@echo "  clean       - Remove build artifacts and output directories"
	@echo "  run         - Build and run the application"
	@echo "  deps        - Download dependencies"
	@echo "  vulncheck   - Run vulnerability check (installs govulncheck if missing)"
	@echo "  lint        - Run linter (installs golangci-lint if missing)"
