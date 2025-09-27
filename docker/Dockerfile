# zssh Docker Container - Optimized for Production
# Multi-stage build for minimal image size

# Build stage
FROM alpine:3.19 AS builder

# Install Zig and build dependencies
RUN apk add --no-cache \
    curl \
    xz \
    musl-dev \
    linux-headers \
    git

# Install Zig
ARG ZIG_VERSION=0.16.0-dev
RUN curl -L "https://ziglang.org/builds/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /opt \
    && ln -s /opt/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/local/bin/zig

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build zssh with optimizations
RUN zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl

# Runtime stage
FROM alpine:3.19 AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    && addgroup -g 2222 zssh \
    && adduser -D -s /bin/sh -u 2222 -G zssh zssh

# Create necessary directories
RUN mkdir -p /etc/zssh /var/log/zssh /var/run/zssh /home/zssh/.ssh \
    && chown -R zssh:zssh /etc/zssh /var/log/zssh /var/run/zssh /home/zssh

# Copy built binaries from builder stage
COPY --from=builder /build/zig-out/bin/zssh /usr/local/bin/zssh
COPY --from=builder /build/zig-out/bin/zsshd /usr/local/bin/zsshd
COPY --from=builder /build/zig-out/bin/zssh-keygen /usr/local/bin/zssh-keygen

# Copy configuration files
COPY docker/zsshd_config /etc/zssh/zsshd_config
COPY docker/entrypoint.sh /entrypoint.sh

# Generate host keys
RUN zssh-keygen -t ed25519 -f /etc/zssh/ssh_host_ed25519_key -N "" -C "zssh-docker-host-key" \
    && zssh-keygen -t rsa -b 4096 -f /etc/zssh/ssh_host_rsa_key -N "" -C "zssh-docker-host-key" \
    && chmod 600 /etc/zssh/ssh_host_* \
    && chmod 644 /etc/zssh/ssh_host_*.pub \
    && chown root:root /etc/zssh/ssh_host_*

# Set permissions
RUN chmod +x /entrypoint.sh

# Expose SSH port
EXPOSE 22

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD zssh -o ConnectTimeout=3 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no localhost echo "health check" || exit 1

# Switch to non-root user for runtime (except for privileged port 22)
USER root

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["zsshd", "-D"]

# Labels for metadata
LABEL maintainer="GhostStack <contact@ghoststack.dev>"
LABEL version="2.0.0"
LABEL description="High-performance SSH server with QUIC transport and advanced features"
LABEL org.opencontainers.image.title="zssh"
LABEL org.opencontainers.image.description="SSH 2.0 server and client with modern transport protocols"
LABEL org.opencontainers.image.vendor="GhostStack"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.schema-version="1.0"