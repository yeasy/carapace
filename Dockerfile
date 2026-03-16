# Multi-stage build for Carapace security scanning
# Stage 1: Builder
FROM node:20-alpine AS builder

LABEL maintainer="Albert Yang <albert@carapace.dev>"
LABEL description="Carapace - AI Agent Runtime Security Monitoring"
LABEL version="0.7.0"

WORKDIR /build

# Copy package files
COPY package.json ./
COPY packages/ ./packages/

# Install dependencies and build
RUN npm install && npm run build

# Stage 2: Runtime
FROM node:20-alpine

LABEL maintainer="Albert Yang <albert@carapace.dev>"
LABEL description="Carapace - AI Agent Runtime Security Monitoring"
LABEL version="0.7.0"

WORKDIR /app

# Copy built application from builder
COPY --from=builder /build/ .

# Remove dev dependencies to keep image small
RUN npm prune --omit=dev 2>/dev/null || true

# Expose dashboard port
EXPOSE 9877

# Create scan volume mount point
VOLUME ["/scan"]

# Set working directory for scanning
WORKDIR /scan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node /app/packages/cli/dist/index.js version || exit 1

# Default command — override with: demo, dashboard, scan, test-rule, etc.
ENTRYPOINT ["node", "/app/packages/cli/dist/index.js"]
CMD ["demo", "--port", "9877"]
