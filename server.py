#!/usr/bin/env python3
"""
SMTP Tunnel Server - Fast Binary Mode

Version: 1.3.0

Protocol:
1. SMTP handshake (EHLO, STARTTLS, AUTH) - looks like real SMTP
2. After AUTH success, switch to binary streaming mode
3. Full-duplex binary protocol - no more SMTP overhead

Features:
- Multi-user support with per-user secrets
- Per-user IP whitelist
- Per-user logging (optional)
"""

import asyncio
import ssl
import logging
import argparse
import struct
import os
from typing import Dict, Optional
from dataclasses import dataclass

from common import (
    TunnelCrypto, load_config, load_users, ServerConfig, UserConfig, IPWhitelist
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smtp-tunnel-server')


# ============================================================================
# Binary Protocol (used after SMTP handshake)
# ============================================================================

# Frame types
FRAME_DATA = 0x01
FRAME_CONNECT = 0x02
FRAME_CONNECT_OK = 0x03
FRAME_CONNECT_FAIL = 0x04
FRAME_CLOSE = 0x05

def make_frame(frame_type: int, channel_id: int, payload: bytes = b'') -> bytes:
    """Create a binary frame: type(1) + channel(2) + length(2) + payload"""
    return struct.pack('>BHH', frame_type, channel_id, len(payload)) + payload

def parse_frame_header(data: bytes):
    """Parse frame header, returns (type, channel_id, payload_len) or None"""
    if len(data) < 5:
        return None
    frame_type, channel_id, payload_len = struct.unpack('>BHH', data[:5])
    return frame_type, channel_id, payload_len

FRAME_HEADER_SIZE = 5


# ============================================================================
# Channel - A tunneled TCP connection
# ============================================================================

@dataclass
class Channel:
    channel_id: int
    host: str
    port: int
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    connected: bool = False


# ============================================================================
# Tunnel Session
# ============================================================================

class TunnelSession:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        config: ServerConfig,
        ssl_context: ssl.SSLContext,
        users: Dict[str, UserConfig]
    ):
        self.reader = reader
        self.writer = writer
        self.config = config
        self.ssl_context = ssl_context
        self.users = users
        self.authenticated = False
        self.binary_mode = False
        self.channels: Dict[int, Channel] = {}
        self.write_lock = asyncio.Lock()

        # User info (set after authentication)
        self.username: Optional[str] = None
        self.user_config: Optional[UserConfig] = None

        peer = writer.get_extra_info('peername')
        self.client_ip = peer[0] if peer else "unknown"
        self.peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"

    def _log(self, level: int, msg: str):
        """Log message with optional user info."""
        if self.user_config and not self.user_config.logging:
            return  # Logging disabled for this user

        if self.username:
            logger.log(level, f"[{self.username}] {msg}")
        else:
            logger.log(level, msg)

    async def run(self):
        """Main session handler."""
        logger.info(f"Connection from {self.peer_str}")

        try:
            # Phase 1: SMTP handshake
            if not await self._smtp_handshake():
                return

            self._log(logging.INFO, f"Authenticated, entering binary mode: {self.peer_str}")

            # Phase 2: Binary streaming mode
            await self._binary_mode()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._log(logging.ERROR, f"Session error: {e}")
        finally:
            await self._cleanup()
            self._log(logging.INFO, f"Session ended: {self.peer_str}")

    async def _smtp_handshake(self) -> bool:
        """Do SMTP handshake - this is what DPI sees."""
        try:
            # Send greeting
            await self._send_line(f"220 {self.config.hostname} ESMTP Postfix (Ubuntu)")

            # Wait for EHLO
            line = await self._read_line()
            if not line or not line.upper().startswith(('EHLO', 'HELO')):
                return False

            # Send capabilities
            await self._send_line(f"250-{self.config.hostname}")
            await self._send_line("250-STARTTLS")
            await self._send_line("250-AUTH PLAIN LOGIN")
            await self._send_line("250 8BITMIME")

            # Wait for STARTTLS
            line = await self._read_line()
            if not line or line.upper() != 'STARTTLS':
                return False

            await self._send_line("220 2.0.0 Ready to start TLS")

            # Upgrade to TLS
            await self._upgrade_tls()

            # Wait for EHLO again
            line = await self._read_line()
            if not line or not line.upper().startswith(('EHLO', 'HELO')):
                return False

            await self._send_line(f"250-{self.config.hostname}")
            await self._send_line("250-AUTH PLAIN LOGIN")
            await self._send_line("250 8BITMIME")

            # Wait for AUTH
            line = await self._read_line()
            if not line or not line.upper().startswith('AUTH'):
                return False

            parts = line.split(' ', 2)
            if len(parts) < 3:
                await self._send_line("535 5.7.8 Authentication failed")
                return False

            token = parts[2]

            # Multi-user authentication
            valid, username = TunnelCrypto.verify_auth_token_multi_user(token, self.users)

            if not valid or not username:
                logger.warning(f"Authentication failed from {self.peer_str}")
                await self._send_line("535 5.7.8 Authentication failed")
                return False

            # Get user config
            self.username = username
            self.user_config = self.users.get(username)

            # Check per-user IP whitelist
            if self.user_config and self.user_config.whitelist:
                user_whitelist = IPWhitelist(self.user_config.whitelist)
                if not user_whitelist.is_allowed(self.client_ip):
                    logger.warning(f"User {username} not allowed from IP {self.client_ip}")
                    await self._send_line("535 5.7.8 Authentication failed")
                    return False

            await self._send_line("235 2.7.0 Authentication successful")
            self.authenticated = True

            # Signal binary mode - client sends special marker
            line = await self._read_line()
            if line == "BINARY":
                await self._send_line("299 Binary mode activated")
                self.binary_mode = True
                return True

            return False

        except Exception as e:
            logger.error(f"Handshake error: {e}")
            return False

    async def _upgrade_tls(self):
        """Upgrade connection to TLS."""
        transport = self.writer.transport
        protocol = self.writer._protocol
        loop = asyncio.get_event_loop()

        new_transport = await loop.start_tls(
            transport, protocol, self.ssl_context, server_side=True
        )

        self.writer._transport = new_transport
        self.reader._transport = new_transport
        logger.debug(f"TLS established: {self.peer_str}")

    async def _send_line(self, line: str):
        """Send SMTP line."""
        self.writer.write(f"{line}\r\n".encode())
        await self.writer.drain()

    async def _read_line(self) -> Optional[str]:
        """Read SMTP line."""
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=60.0)
            if not data:
                return None
            return data.decode('utf-8', errors='replace').strip()
        except:
            return None

    async def _binary_mode(self):
        """Handle binary streaming mode - this is FAST."""
        buffer = b''

        while True:
            # Read data
            try:
                chunk = await asyncio.wait_for(self.reader.read(65536), timeout=60.0)
                if not chunk:
                    self._log(logging.DEBUG, "Connection closed by client")
                    break
                buffer += chunk
            except asyncio.TimeoutError:
                # Check if connection is still alive
                if self.writer.is_closing():
                    break
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                self._log(logging.DEBUG, f"Connection error: {e}")
                break

            # Process complete frames
            while len(buffer) >= FRAME_HEADER_SIZE:
                header = parse_frame_header(buffer)
                if not header:
                    break

                frame_type, channel_id, payload_len = header
                total_len = FRAME_HEADER_SIZE + payload_len

                if len(buffer) < total_len:
                    break

                payload = buffer[FRAME_HEADER_SIZE:total_len]
                buffer = buffer[total_len:]

                await self._handle_frame(frame_type, channel_id, payload)

    async def _handle_frame(self, frame_type: int, channel_id: int, payload: bytes):
        """Handle a binary frame."""
        if frame_type == FRAME_CONNECT:
            await self._handle_connect(channel_id, payload)
        elif frame_type == FRAME_DATA:
            await self._handle_data(channel_id, payload)
        elif frame_type == FRAME_CLOSE:
            await self._handle_close(channel_id)

    async def _handle_connect(self, channel_id: int, payload: bytes):
        """Handle CONNECT request."""
        try:
            # Parse: host_len(1) + host + port(2)
            host_len = payload[0]
            host = payload[1:1+host_len].decode('utf-8')
            port = struct.unpack('>H', payload[1+host_len:3+host_len])[0]

            logger.info(f"CONNECT ch={channel_id} -> {host}:{port}")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=30.0
                )

                channel = Channel(
                    channel_id=channel_id,
                    host=host,
                    port=port,
                    reader=reader,
                    writer=writer,
                    connected=True
                )
                self.channels[channel_id] = channel

                # Start reading from destination
                asyncio.create_task(self._channel_reader(channel))

                # Send success
                await self._send_frame(FRAME_CONNECT_OK, channel_id)
                logger.info(f"CONNECTED ch={channel_id}")

            except Exception as e:
                logger.error(f"Connect failed: {e}")
                await self._send_frame(FRAME_CONNECT_FAIL, channel_id, str(e).encode()[:100])

        except Exception as e:
            logger.error(f"Handle connect error: {e}")
            await self._send_frame(FRAME_CONNECT_FAIL, channel_id)

    async def _handle_data(self, channel_id: int, payload: bytes):
        """Forward data to destination."""
        channel = self.channels.get(channel_id)
        if channel and channel.connected and channel.writer:
            try:
                channel.writer.write(payload)
                await channel.writer.drain()
            except:
                await self._close_channel(channel)

    async def _handle_close(self, channel_id: int):
        """Close channel."""
        channel = self.channels.get(channel_id)
        if channel:
            await self._close_channel(channel)

    async def _channel_reader(self, channel: Channel):
        """Read from destination and send to client."""
        try:
            while channel.connected:
                data = await asyncio.wait_for(
                    channel.reader.read(32768),
                    timeout=300.0
                )
                if not data:
                    break

                await self._send_frame(FRAME_DATA, channel.channel_id, data)

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Channel reader error: {e}")
        finally:
            if channel.connected:
                await self._send_frame(FRAME_CLOSE, channel.channel_id)
                await self._close_channel(channel)

    async def _send_frame(self, frame_type: int, channel_id: int, payload: bytes = b''):
        """Send binary frame to client."""
        if self.writer.is_closing():
            return
        try:
            async with self.write_lock:
                frame = make_frame(frame_type, channel_id, payload)
                self.writer.write(frame)
                await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    async def _close_channel(self, channel: Channel):
        """Close a channel."""
        if not channel.connected:
            return
        channel.connected = False

        if channel.writer:
            try:
                channel.writer.close()
                await channel.writer.wait_closed()
            except:
                pass

        self.channels.pop(channel.channel_id, None)

    async def _cleanup(self):
        """Cleanup session."""
        for channel in list(self.channels.values()):
            await self._close_channel(channel)
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except:
            pass


# ============================================================================
# Server
# ============================================================================

class TunnelServer:
    def __init__(self, config: ServerConfig, users: Dict[str, UserConfig]):
        self.config = config
        self.users = users
        self.ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.config.cert_file, self.config.key_file)
        return ctx

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session = TunnelSession(reader, writer, self.config, self.ssl_context, self.users)
        await session.run()

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client,
            self.config.host,
            self.config.port
        )
        addr = server.sockets[0].getsockname()
        logger.info(f"SMTP Tunnel Server on {addr[0]}:{addr[1]}")
        logger.info(f"Hostname: {self.config.hostname}")
        logger.info(f"Users loaded: {len(self.users)}")

        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description='SMTP Tunnel Server')
    parser.add_argument('--config', '-c', default='config.yaml')
    parser.add_argument('--users', '-u', default=None, help='Users file (default: from config or users.yaml)')
    parser.add_argument('--debug', '-d', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config_data = load_config(args.config)
    except FileNotFoundError:
        config_data = {}

    server_conf = config_data.get('server', {})

    config = ServerConfig(
        host=server_conf.get('host', '0.0.0.0'),
        port=server_conf.get('port', 587),
        hostname=server_conf.get('hostname', 'mail.example.com'),
        cert_file=server_conf.get('cert_file', 'server.crt'),
        key_file=server_conf.get('key_file', 'server.key'),
        users_file=server_conf.get('users_file', 'users.yaml'),
        log_users=server_conf.get('log_users', True),
    )

    # Load users file (command line override or from config)
    users_file = args.users or config.users_file
    users = load_users(users_file)

    if not users:
        logger.error(f"No users configured! Please create {users_file}")
        logger.error("Use smtp-tunnel-adduser to add users")
        return 1

    if not os.path.exists(config.cert_file):
        logger.error(f"Certificate not found: {config.cert_file}")
        return 1

    server = TunnelServer(config, users)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Server stopped")

    return 0


if __name__ == '__main__':
    exit(main())
