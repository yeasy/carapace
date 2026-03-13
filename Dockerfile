# Multi-stage build for Carapace security scanning
# Stage 1: Builder
FROM node:20-alpine AS builder

LABEL maintainer="Albert Yang <albert@carapace.dev>"
LABEL description="Carapace - AI Agent Runtime Security Monitoring"
LABEL version="0.6.0"

WORKDIR /build

# Copy root package files
COPY package.json package-lock.json ./

# Copy all packages
COPY packages/ ./packages/

# Install dependencies and build
RUN npm ci && npm run build

# Stage 2: Runtime
FROM node:20-alpine

LABEL maintainer="Albert Yang <albert@carapace.dev>"
LABEL description="Carapace - AI Agent Runtime Security Monitoring"
LABEL version="0.6.0"

WORKDIR /app

# Copy built application from builder
COPY --from=builder /build/ .

# Remove dev dependencies to keep image small
RUN npm ci --omit=dev

# Create scan volume mount point
VOLUME ["/scan"]

# Set working directory for scanning
WORKDIR /scan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node /app/packages/cli/dist/index.js --help || exit 1

# Default command is 'scan' but users can override with any carapace command
ENTRYPOINT ["node", "/app/packages/cli/dist/index.js"]
CMD ["scan"]
