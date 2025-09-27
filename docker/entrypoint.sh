#!/bin/sh
# zssh Docker entrypoint script

set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to generate missing host keys
generate_host_keys() {
    local key_types="ed25519 rsa"

    for key_type in $key_types; do
        local key_file="/etc/zssh/ssh_host_${key_type}_key"

        if [ ! -f "$key_file" ]; then
            log "Generating $key_type host key..."

            case $key_type in
                ed25519)
                    zssh-keygen -t ed25519 -f "$key_file" -N "" -C "zssh-docker-$key_type"
                    ;;
                rsa)
                    zssh-keygen -t rsa -b 4096 -f "$key_file" -N "" -C "zssh-docker-$key_type"
                    ;;
            esac

            chmod 600 "$key_file"
            chmod 644 "${key_file}.pub"
            chown root:root "$key_file" "${key_file}.pub"

            log "Generated $key_type host key"
        fi
    done
}

# Function to display host key fingerprints
show_fingerprints() {
    log "Host key fingerprints:"
    for key_file in /etc/zssh/ssh_host_*_key.pub; do
        if [ -f "$key_file" ]; then
            zssh-keygen -l -f "$key_file"
        fi
    done
}

# Function to create banner
create_banner() {
    cat > /etc/zssh/banner.txt << 'EOF'
 ________  ________  ________  ___  ___
|\_____  \|\   ____\|\   ____\|\  \|\  \
 \|___/  /\ \  \___|\ \  \___|\ \  \\\  \
     /  / /\ \_____  \ \_____  \ \   __  \
    /  /_/__\|____|\  \|____|\  \ \  \ \  \
   |\________\____\_\  \____\_\  \ \__\ \__\
    \|_______|\_________\\_________\|__|\__|
             \|_________\|_________|

Welcome to zssh - High-Performance SSH Server
Container Version: 2.0.0
Features: QUIC Transport, Multiplexing, OIDC Auth, SFTP v6

EOF
}

# Function to setup user accounts from environment
setup_users() {
    # Check for SSH_USERS environment variable
    if [ -n "$SSH_USERS" ]; then
        log "Setting up SSH users from environment..."

        # Format: username:password:uid:gid:comment
        echo "$SSH_USERS" | tr ',' '\n' | while read -r user_spec; do
            if [ -n "$user_spec" ]; then
                username=$(echo "$user_spec" | cut -d: -f1)
                password=$(echo "$user_spec" | cut -d: -f2)
                uid=$(echo "$user_spec" | cut -d: -f3)
                gid=$(echo "$user_spec" | cut -d: -f4)
                comment=$(echo "$user_spec" | cut -d: -f5)

                # Create user if it doesn't exist
                if ! id "$username" >/dev/null 2>&1; then
                    adduser -D -s /bin/sh ${uid:+-u "$uid"} ${gid:+-G "$gid"} "$username"
                    echo "$username:$password" | chpasswd

                    # Create SSH directory
                    mkdir -p "/home/$username/.ssh"
                    chmod 700 "/home/$username/.ssh"
                    chown "$username:$username" "/home/$username/.ssh"

                    log "Created user: $username"
                fi
            fi
        done
    fi

    # Setup authorized keys from environment
    if [ -n "$SSH_AUTHORIZED_KEYS" ]; then
        log "Setting up authorized keys..."

        # Default to zssh user if no specific user provided
        target_user=${SSH_USER:-zssh}

        if id "$target_user" >/dev/null 2>&1; then
            echo "$SSH_AUTHORIZED_KEYS" > "/home/$target_user/.ssh/authorized_keys"
            chmod 600 "/home/$target_user/.ssh/authorized_keys"
            chown "$target_user:$target_user" "/home/$target_user/.ssh/authorized_keys"

            log "Authorized keys setup for user: $target_user"
        fi
    fi
}

# Function to configure zsshd based on environment
configure_zsshd() {
    local config_file="/etc/zssh/zsshd_config"

    # Override port if specified
    if [ -n "$SSH_PORT" ]; then
        sed -i "s/^Port 22/Port $SSH_PORT/" "$config_file"
        log "SSH port set to: $SSH_PORT"
    fi

    # Enable/disable password authentication
    if [ "$DISABLE_PASSWORD_AUTH" = "true" ]; then
        sed -i "s/^PasswordAuthentication yes/PasswordAuthentication no/" "$config_file"
        log "Password authentication disabled"
    fi

    # Enable/disable QUIC transport
    if [ "$DISABLE_QUIC" = "true" ]; then
        sed -i "s/^EnableQuicTransport yes/EnableQuicTransport no/" "$config_file"
        log "QUIC transport disabled"
    fi

    # Set log level
    if [ -n "$LOG_LEVEL" ]; then
        sed -i "s/^LogLevel INFO/LogLevel $LOG_LEVEL/" "$config_file"
        log "Log level set to: $LOG_LEVEL"
    fi

    # Configure OIDC if enabled
    if [ -n "$OIDC_CLIENT_ID" ] && [ -n "$OIDC_CLIENT_SECRET" ]; then
        {
            echo ""
            echo "# OIDC Configuration"
            echo "OIDCClientId $OIDC_CLIENT_ID"
            echo "OIDCClientSecret $OIDC_CLIENT_SECRET"
            [ -n "$OIDC_PROVIDER" ] && echo "OIDCProvider $OIDC_PROVIDER"
            [ -n "$OIDC_REDIRECT_URI" ] && echo "OIDCRedirectUri $OIDC_REDIRECT_URI"
        } >> "$config_file"

        log "OIDC authentication configured"
    fi
}

# Function to test configuration
test_config() {
    log "Testing zsshd configuration..."

    if zsshd -t -f /etc/zssh/zsshd_config; then
        log "Configuration test passed"
    else
        log "ERROR: Configuration test failed"
        exit 1
    fi
}

# Function to handle graceful shutdown
graceful_shutdown() {
    log "Received shutdown signal, stopping zsshd..."

    if [ -f "/var/run/zssh/zsshd.pid" ]; then
        kill -TERM "$(cat /var/run/zssh/zsshd.pid)" 2>/dev/null || true

        # Wait for graceful shutdown
        for i in $(seq 1 10); do
            if ! kill -0 "$(cat /var/run/zssh/zsshd.pid)" 2>/dev/null; then
                break
            fi
            sleep 1
        done

        # Force kill if still running
        kill -KILL "$(cat /var/run/zssh/zsshd.pid)" 2>/dev/null || true
    fi

    log "zsshd stopped"
    exit 0
}

# Set up signal handlers
trap graceful_shutdown TERM INT

# Main setup
main() {
    log "Starting zssh Docker container setup..."

    # Create necessary directories
    mkdir -p /var/run/zssh /var/log/zssh
    chown zssh:zssh /var/run/zssh /var/log/zssh

    # Generate host keys if needed
    generate_host_keys

    # Create banner
    create_banner

    # Setup users and keys
    setup_users

    # Configure zsshd
    configure_zsshd

    # Test configuration
    test_config

    # Show host key fingerprints
    show_fingerprints

    log "zssh container setup complete"

    # Execute the main command
    exec "$@"
}

# Run main setup if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ] || [ "${0}" = "/entrypoint.sh" ]; then
    main "$@"
fi