# Development Container

This directory contains the development container configuration for the GoFile project.

## Features

- Go 1.21 development environment
- Pre-installed development tools (goimports, golint, golangci-lint, staticcheck)
- File command and libmagic for testing
- VS Code extensions for Go development
- Automatic setup of test environment

## Usage

### VS Code

1. Install the "Dev Containers" extension
2. Open the project in VS Code
3. Press `Ctrl+Shift+P` and select "Dev Containers: Reopen in Container"
4. Wait for the container to build and setup to complete

### Manual Setup

If you need to run the setup manually:

```bash
bash .devcontainer/setup.sh
```

## Included Tools

- **Go Tools**: goimports, golint, golangci-lint, staticcheck
- **System Tools**: file, libmagic-dev, hexdump, xxd, tree
- **VS Code Extensions**: Go, JSON, YAML, Makefile Tools, Spell Checker

## Environment Variables

- `GO111MODULE=on`
- `GOPROXY=https://proxy.golang.org,direct`
- `GOSUMDB=sum.golang.org`

## Post-Creation Commands

The container automatically runs:
1. Install Go development tools
2. Install system dependencies
3. Initialize Go module (if needed)
4. Download Go dependencies
5. Setup test environment (if Makefile exists)

## Customization

To customize the environment:
- Edit `devcontainer.json` for VS Code settings and extensions
- Edit `setup.sh` for additional setup commands
- Use the optional `Dockerfile` for system-level customizations
