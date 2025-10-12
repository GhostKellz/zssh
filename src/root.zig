//! zssh - Zig SSH 2.0 Client & Server Library
//! 
//! A modern, Zig-native implementation of the SSH 2.0 protocol.
//! Provides secure remote login, tunneling, and file transfer support with a clean async architecture.

const std = @import("std");

// Core modules
pub const transport = @import("transport/transport.zig");
pub const auth = @import("auth/auth.zig");
pub const client = @import("client/client.zig");
pub const server = @import("server/server.zig");

// Easy client API for shell integration (GShell)
pub const easy_client = @import("client/easy_client.zig");

// Advanced SSH features
pub const ssh_config = @import("client/ssh_config.zig");
pub const known_hosts = @import("client/known_hosts.zig");
pub const ssh_agent = @import("client/ssh_agent.zig");
pub const proxy_command = @import("client/proxy_command.zig");
pub const authorized_keys = @import("server/authorized_keys.zig");

// Advanced transport features
pub const x11_forward = @import("transport/x11_forward.zig");
pub const socks_proxy = @import("transport/socks_proxy.zig");
pub const multiplex = @import("transport/multiplex.zig");

// Transport layer components
pub const kex = @import("transport/kex.zig");
pub const encryption = @import("transport/encryption.zig");
pub const channel = @import("transport/channel.zig");
pub const packet = @import("transport/packet.zig");

// Cryptographic support
pub const crypto = @import("crypto/crypto.zig");

// Session management
pub const session = @import("server/session.zig");

// SFTP subsystem
pub const sftp = @import("sftp/sftp.zig");

// Main API exports
pub const Client = client.Client;
pub const Server = server.Server;

// Easy API exports for shell integration
pub const connect = easy_client.connect;
pub const ConnectOptions = easy_client.ConnectOptions;
pub const EasyAuthMethod = easy_client.AuthMethod;
pub const SshSession = easy_client.SshSession;
pub const ExecResult = easy_client.ExecResult;
pub const JumpHost = easy_client.JumpHost;
pub const PortForward = easy_client.PortForward;

// Protocol constants
pub const SSH_VERSION = "SSH-2.0-zssh_0.2";

// Common types
pub const KeyExchangeAlgorithm = kex.KexAlgorithm;
pub const EncryptionAlgorithm = encryption.EncryptionAlgorithm;
pub const ChannelType = channel.ChannelType;
pub const AuthMethod = auth.AuthMethod;

// Error types
pub const SshError = transport.TransportError || 
                    auth.AuthError || 
                    kex.KexError || 
                    encryption.EncryptionError || 
                    channel.ChannelError ||
                    session.SessionError ||
                    sftp.SftpError;

test "zssh module imports" {
    _ = transport;
    _ = auth;
    _ = client;
    _ = server;
    _ = kex;
    _ = encryption;
    _ = channel;
    _ = packet;
    _ = crypto;
    _ = session;
    _ = sftp;
}
