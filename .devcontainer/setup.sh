#!/bin/bash

set -e

echo "Setting up GoFile development environment..."

# Install additional tools
echo "Installing development tools..."
go install golang.org/x/tools/cmd/goimports@latest
go install golang.org/x/lint/golint@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install honnef.co/go/tools/cmd/staticcheck@latest

# Install file command for testing
echo "Installing file command..."
sudo apt-get update
sudo apt-get install -y file libmagic-dev

# Verify installations
echo "Verifying installations..."
go version
file --version
which file

# Initialize Go module if not exists
if [ ! -f "go.mod" ]; then
    echo "Initializing Go module..."
    go mod init github.com/shirou/gofile
fi

# Download dependencies
echo "Downloading Go dependencies..."
go mod download
go mod tidy

# Setup test environment
echo "Setting up test environment..."
if [ -f "Makefile" ]; then
    make setup-test || echo "Test setup will be run manually"
fi

# Set proper permissions
sudo chown -R vscode:vscode /workspaces
chmod +x scripts/*.sh 2>/dev/null || true

echo "Development environment setup complete!"
echo ""
echo "Available commands:"
echo "  make build       - Build the gofile binary"
echo "  make test        - Run all tests"
echo "  make setup-test  - Setup test environment"
echo "  make bench       - Run benchmarks"
echo ""
echo "Happy coding!"
