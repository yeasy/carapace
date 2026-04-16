# Multi-stage build for Carapace security scanning
# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /build

# Copy package files for dependency installation
COPY package.json ./
COPY packages/ ./packages/

# Install dependencies and build
RUN npm install --ignore-scripts && npm run build

# Stage 2: Runtime
FROM node:20-alpine

LABEL maintainer="yeasy <yangbaohua@gmail.com>"
LABEL description="Carapace - AI Agent Runtime Security Monitoring"

WORKDIR /app

# Copy only runtime artifacts from builder
COPY --from=builder /build/package.json ./
COPY --from=builder /build/node_modules/ ./node_modules/
COPY --from=builder /build/packages/core/package.json ./packages/core/
COPY --from=builder /build/packages/core/dist/ ./packages/core/dist/
COPY --from=builder /build/packages/adapter-openclaw/package.json ./packages/adapter-openclaw/
COPY --from=builder /build/packages/adapter-openclaw/dist/ ./packages/adapter-openclaw/dist/
COPY --from=builder /build/packages/adapter-mcp/package.json ./packages/adapter-mcp/
COPY --from=builder /build/packages/adapter-mcp/dist/ ./packages/adapter-mcp/dist/
COPY --from=builder /build/packages/adapter-langchain/package.json ./packages/adapter-langchain/
COPY --from=builder /build/packages/adapter-langchain/dist/ ./packages/adapter-langchain/dist/
COPY --from=builder /build/packages/dashboard/package.json ./packages/dashboard/
COPY --from=builder /build/packages/dashboard/dist/ ./packages/dashboard/dist/
COPY --from=builder /build/packages/cli/package.json ./packages/cli/
COPY --from=builder /build/packages/cli/dist/ ./packages/cli/dist/

# Remove dev dependencies to keep image small
RUN npm prune --omit=dev || true; npm cache clean --force || true

# Run as non-root user for security
RUN addgroup -S carapace && adduser -S carapace -G carapace

# Create scan volume mount point with correct ownership before switching user
RUN mkdir -p /scan && chown carapace:carapace /scan
VOLUME ["/scan"]

USER carapace

# Expose dashboard port
EXPOSE 9877

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:9877/api/health || exit 1

# Default command — override with: demo, dashboard, scan, test-rule, etc.
ENTRYPOINT ["node", "/app/packages/cli/dist/index.js"]
CMD ["demo", "--port", "9877"]
