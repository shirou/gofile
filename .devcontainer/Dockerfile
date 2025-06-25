# Optional custom Dockerfile for additional customizations
FROM mcr.microsoft.com/devcontainers/go:1-1.21-bullseye

# Install additional system packages
RUN apt-get update && apt-get install -y \
    file \
    libmagic-dev \
    hexdump \
    xxd \
    tree \
    && rm -rf /var/lib/apt/lists/*

# Set up Go environment
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org

# Install Go tools
RUN go install golang.org/x/tools/cmd/goimports@latest && \
    go install golang.org/x/lint/golint@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest

# Create workspace directory
WORKDIR /workspaces/gofile

# Set proper ownership
RUN chown -R vscode:vscode /go
