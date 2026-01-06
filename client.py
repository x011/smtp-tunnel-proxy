#!/usr/bin/env python3
"""
SMTP Tunnel Client - Fast Binary Mode

Version: 1.3.0

Protocol:
1. SMTP handshake (EHLO, STARTTLS, AUTH) - looks like real SMTP
2. After AUTH, send "BINARY" to switch to streaming mode
3. Full-duplex binary protocol - data flows as fast as TCP allows

Features:
- Multi-user support (username + secret authentication)
"""

import asyncio
import ssl
import logging
import argparse
import struct
import time
import os
import socket
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from common import TunnelCrypto, load_config, ClientConfig

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smtp-tunnel-client')


# ============================================================================
# Binary Protocol
# ============================================================================

FRAME_DATA = 0x01
FRAME_CONNECT = 0x02
FRAME_CONNECT_OK = 0x03
FRAME_CONNECT_FAIL = 0x04
FRAME_CLOSE = 0x05
FRAME_HEADER_SIZE = 5

def make_frame(frame_type: int, channel_id: int, payload: bytes = b'') -> bytes:
    return struct.pack('>BHH', frame_type, channel_id, len(payload)) + payload

def make_connect_payload(host: str, port: int) -> bytes:
    host_bytes = host.encode('utf-8')
    return struct.pack('>B', len(host_bytes)) + host_bytes + struct.pack('>H', port)


# ============================================================================
# SOCKS5
# ============================================================================

class SOCKS5:
    VERSION = 0x05
    AUTH_NONE = 0x00
    CMD_CONNECT = 0x01
    ATYP_IPV4 = 0x01
    ATYP_DOMAIN = 0x03
    ATYP_IPV6 = 0x04
    REP_SUCCESS = 0x00
    REP_FAILURE = 0x01


@dataclass
class Channel:
    channel_id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    host: str
    port: int
    connected: bool = False


# ============================================================================
# Tunnel Client
# ============================================================================

class TunnelClient:
    def __init__(self, config: ClientConfig, ca_cert: str = None):
        self.config = config
        self.ca_cert = ca_cert

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False

        self.channels: Dict[int, Channel] = {}
        self.next_channel_id = 1
        self.channel_lock = asyncio.Lock()

        self.connect_events: Dict[int, asyncio.Event] = {}
        self.connect_results: Dict[int, bool] = {}

        self.write_lock = asyncio.Lock()

    async def connect(self) -> bool:
        """Connect and do SMTP handshake, then switch to binary mode."""
        try:
            logger.info(f"Connecting to {self.config.server_host}:{self.config.server_port}")

            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.server_host, self.config.server_port),
                timeout=30.0
            )

            # SMTP Handshake
            if not await self._smtp_handshake():
                return False

            self.connected = True
            logger.info("Connected - binary mode active")
            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    async def _smtp_handshake(self) -> bool:
        """Do SMTP handshake then switch to binary."""
        try:
            # Wait for greeting
            line = await self._read_line()
            if not line or not line.startswith('220'):
                return False

            # EHLO
            await self._send_line("EHLO tunnel-client.local")
            if not await self._expect_250():
                return False

            # STARTTLS
            await self._send_line("STARTTLS")
            line = await self._read_line()
            if not line or not line.startswith('220'):
                return False

            # Upgrade TLS
            await self._upgrade_tls()

            # EHLO again
            await self._send_line("EHLO tunnel-client.local")
            if not await self._expect_250():
                return False

            # AUTH
            timestamp = int(time.time())
            crypto = TunnelCrypto(self.config.secret, is_server=False)
            token = crypto.generate_auth_token(timestamp, self.config.username)

            await self._send_line(f"AUTH PLAIN {token}")
            line = await self._read_line()
            if not line or not line.startswith('235'):
                logger.error(f"Auth failed: {line}")
                return False

            # Switch to binary mode
            await self._send_line("BINARY")
            line = await self._read_line()
            if not line or not line.startswith('299'):
                logger.error(f"Binary mode failed: {line}")
                return False

            return True

        except Exception as e:
            logger.error(f"Handshake error: {e}")
            return False

    async def _upgrade_tls(self):
        """Upgrade to TLS."""
        ssl_context = ssl.create_default_context()
        if self.ca_cert and os.path.exists(self.ca_cert):
            ssl_context.load_verify_locations(self.ca_cert)
        else:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        transport = self.writer.transport
        protocol = self.writer._protocol
        loop = asyncio.get_event_loop()

        new_transport = await loop.start_tls(
            transport, protocol, ssl_context,
            server_hostname=self.config.server_host
        )

        self.writer._transport = new_transport
        self.reader._transport = new_transport
        logger.debug("TLS established")

    async def _send_line(self, line: str):
        self.writer.write(f"{line}\r\n".encode())
        await self.writer.drain()

    async def _read_line(self) -> Optional[str]:
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=60.0)
            if not data:
                return None
            return data.decode('utf-8', errors='replace').strip()
        except:
            return None

    async def _expect_250(self) -> bool:
        while True:
            line = await self._read_line()
            if not line:
                return False
            if line.startswith('250 '):
                return True
            if line.startswith('250-'):
                continue
            return False

    async def start_receiver(self):
        """Start background task to receive frames from server."""
        asyncio.create_task(self._receiver_loop())

    async def _receiver_loop(self):
        """Receive and dispatch frames from server."""
        buffer = b''

        while self.connected:
            try:
                chunk = await asyncio.wait_for(self.reader.read(65536), timeout=300.0)
                if not chunk:
                    break
                buffer += chunk

                # Process frames
                while len(buffer) >= FRAME_HEADER_SIZE:
                    frame_type, channel_id, payload_len = struct.unpack('>BHH', buffer[:5])
                    total_len = FRAME_HEADER_SIZE + payload_len

                    if len(buffer) < total_len:
                        break

                    payload = buffer[FRAME_HEADER_SIZE:total_len]
                    buffer = buffer[total_len:]

                    await self._handle_frame(frame_type, channel_id, payload)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Receiver error: {e}")
                break

        self.connected = False

    async def _handle_frame(self, frame_type: int, channel_id: int, payload: bytes):
        """Handle received frame."""
        if frame_type == FRAME_CONNECT_OK:
            if channel_id in self.connect_events:
                self.connect_results[channel_id] = True
                self.connect_events[channel_id].set()

        elif frame_type == FRAME_CONNECT_FAIL:
            if channel_id in self.connect_events:
                self.connect_results[channel_id] = False
                self.connect_events[channel_id].set()

        elif frame_type == FRAME_DATA:
            channel = self.channels.get(channel_id)
            if channel and channel.connected:
                try:
                    channel.writer.write(payload)
                    await channel.writer.drain()
                except:
                    await self._close_channel(channel)

        elif frame_type == FRAME_CLOSE:
            channel = self.channels.get(channel_id)
            if channel:
                await self._close_channel(channel)

    async def send_frame(self, frame_type: int, channel_id: int, payload: bytes = b''):
        """Send frame to server."""
        if not self.connected or not self.writer:
            return
        async with self.write_lock:
            try:
                frame = make_frame(frame_type, channel_id, payload)
                self.writer.write(frame)
                await self.writer.drain()
            except Exception:
                self.connected = False

    async def open_channel(self, host: str, port: int) -> Tuple[int, bool]:
        """Open a tunnel channel."""
        if not self.connected:
            return 0, False

        async with self.channel_lock:
            channel_id = self.next_channel_id
            self.next_channel_id += 1

        event = asyncio.Event()
        self.connect_events[channel_id] = event
        self.connect_results[channel_id] = False

        # Send CONNECT
        try:
            payload = make_connect_payload(host, port)
            await self.send_frame(FRAME_CONNECT, channel_id, payload)
        except Exception:
            return channel_id, False

        # Wait for response
        try:
            await asyncio.wait_for(event.wait(), timeout=30.0)
            success = self.connect_results.get(channel_id, False)
        except asyncio.TimeoutError:
            success = False

        self.connect_events.pop(channel_id, None)
        self.connect_results.pop(channel_id, None)

        return channel_id, success

    async def send_data(self, channel_id: int, data: bytes):
        """Send data on channel."""
        await self.send_frame(FRAME_DATA, channel_id, data)

    async def close_channel_remote(self, channel_id: int):
        """Tell server to close channel."""
        await self.send_frame(FRAME_CLOSE, channel_id)

    async def _close_channel(self, channel: Channel):
        """Close local channel."""
        if not channel.connected:
            return
        channel.connected = False

        try:
            channel.writer.close()
            await channel.writer.wait_closed()
        except:
            pass

        self.channels.pop(channel.channel_id, None)

    async def disconnect(self):
        """Disconnect and cleanup."""
        self.connected = False
        for channel in list(self.channels.values()):
            await self._close_channel(channel)
        if self.writer:
            try:
                self.writer.close()
                await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
            except:
                pass
        self.reader = None
        self.writer = None
        self.channels.clear()
        self.connect_events.clear()
        self.connect_results.clear()


# ============================================================================
# SOCKS5 Server
# ============================================================================

class SOCKS5Server:
    def __init__(self, tunnel: TunnelClient, host: str = '127.0.0.1', port: int = 1080):
        self.tunnel = tunnel
        self.host = host
        self.port = port

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle SOCKS5 client."""
        channel = None
        try:
            # Check tunnel is connected
            if not self.tunnel.connected:
                writer.close()
                return

            # SOCKS5 handshake
            data = await reader.read(2)
            if len(data) < 2 or data[0] != SOCKS5.VERSION:
                return

            nmethods = data[1]
            await reader.read(nmethods)

            writer.write(bytes([SOCKS5.VERSION, SOCKS5.AUTH_NONE]))
            await writer.drain()

            # Request
            data = await reader.read(4)
            if len(data) < 4:
                return

            version, cmd, _, atyp = data

            if cmd != SOCKS5.CMD_CONNECT:
                writer.write(bytes([SOCKS5.VERSION, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]))
                await writer.drain()
                return

            # Parse address
            if atyp == SOCKS5.ATYP_IPV4:
                addr_data = await reader.read(4)
                host = socket.inet_ntoa(addr_data)
            elif atyp == SOCKS5.ATYP_DOMAIN:
                length = (await reader.read(1))[0]
                host = (await reader.read(length)).decode()
            elif atyp == SOCKS5.ATYP_IPV6:
                addr_data = await reader.read(16)
                host = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                return

            port_data = await reader.read(2)
            port = struct.unpack('>H', port_data)[0]

            logger.info(f"CONNECT {host}:{port}")

            # Open tunnel
            channel_id, success = await self.tunnel.open_channel(host, port)

            if success:
                writer.write(bytes([SOCKS5.VERSION, SOCKS5.REP_SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0]))
                await writer.drain()

                channel = Channel(
                    channel_id=channel_id,
                    reader=reader,
                    writer=writer,
                    host=host,
                    port=port,
                    connected=True
                )
                self.tunnel.channels[channel_id] = channel

                # Forward loop
                await self._forward_loop(channel)
            else:
                writer.write(bytes([SOCKS5.VERSION, SOCKS5.REP_FAILURE, 0, 1, 0, 0, 0, 0, 0, 0]))
                await writer.drain()

        except Exception as e:
            logger.debug(f"SOCKS error: {e}")
        finally:
            if channel:
                await self.tunnel.close_channel_remote(channel.channel_id)
                await self.tunnel._close_channel(channel)
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _forward_loop(self, channel: Channel):
        """Forward data from SOCKS client to tunnel."""
        try:
            while channel.connected and self.tunnel.connected:
                try:
                    data = await asyncio.wait_for(channel.reader.read(32768), timeout=0.1)
                    if data:
                        await self.tunnel.send_data(channel.channel_id, data)
                    elif data == b'':
                        break
                except asyncio.TimeoutError:
                    continue
        except:
            pass

    async def start(self):
        """Start SOCKS5 server."""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        addr = server.sockets[0].getsockname()
        logger.info(f"SOCKS5 proxy on {addr[0]}:{addr[1]}")

        async with server:
            await server.serve_forever()


# ============================================================================
# Main
# ============================================================================

async def run_client(config: ClientConfig, ca_cert: str):
    """Run client with auto-reconnect."""
    reconnect_delay = 2  # seconds between reconnect attempts
    max_reconnect_delay = 30  # max delay
    current_delay = reconnect_delay

    while True:
        tunnel = TunnelClient(config, ca_cert)

        # Try to connect
        if not await tunnel.connect():
            logger.warning(f"Connection failed, retrying in {current_delay}s...")
            await asyncio.sleep(current_delay)
            current_delay = min(current_delay * 2, max_reconnect_delay)
            continue

        # Connected - reset delay
        current_delay = reconnect_delay

        # Start receiver in background
        receiver_task = asyncio.create_task(tunnel._receiver_loop())

        # Start SOCKS server
        socks = SOCKS5Server(tunnel, config.socks_host, config.socks_port)

        try:
            # Create SOCKS server but don't block on it
            socks_server = await asyncio.start_server(
                socks.handle_client,
                socks.host,
                socks.port,
                reuse_address=True  # Allow quick rebind after restart
            )
            addr = socks_server.sockets[0].getsockname()
            logger.info(f"SOCKS5 proxy on {addr[0]}:{addr[1]}")

            # Wait for either: receiver dies (connection lost) or KeyboardInterrupt
            async with socks_server:
                try:
                    # Wait for receiver to finish (means connection lost)
                    await receiver_task
                except asyncio.CancelledError:
                    pass

            # Connection lost - reconnect immediately
            if tunnel.connected:
                tunnel.connected = False

            logger.warning("Connection lost, reconnecting...")
            current_delay = reconnect_delay  # Reset delay for next failure

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            await tunnel.disconnect()
            return 0
        except OSError as e:
            if "Address already in use" in str(e):
                logger.error(f"Port {socks.port} already in use, waiting...")
                await asyncio.sleep(2)
            else:
                logger.error(f"SOCKS server error: {e}")
        finally:
            await tunnel.disconnect()
            receiver_task.cancel()
            try:
                await receiver_task
            except asyncio.CancelledError:
                pass

        # No delay after connection loss - only delay on connection failure (handled at top of loop)


def main():
    parser = argparse.ArgumentParser(description='SMTP Tunnel Client (Fast)')
    parser.add_argument('--config', '-c', default='config.yaml')
    parser.add_argument('--server', default=None, help='Server domain name (FQDN required for TLS)')
    parser.add_argument('--server-port', type=int, default=None)
    parser.add_argument('--socks-port', '-p', type=int, default=None)
    parser.add_argument('--username', '-u', default=None, help='Username for authentication')
    parser.add_argument('--secret', '-s', default=None)
    parser.add_argument('--ca-cert', default=None)
    parser.add_argument('--debug', '-d', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config_data = load_config(args.config)
    except FileNotFoundError:
        config_data = {}

    client_conf = config_data.get('client', {})

    config = ClientConfig(
        server_host=args.server or client_conf.get('server_host', 'localhost'),
        server_port=args.server_port or client_conf.get('server_port', 587),
        socks_port=args.socks_port or client_conf.get('socks_port', 1080),
        socks_host=client_conf.get('socks_host', '127.0.0.1'),
        username=args.username or client_conf.get('username', ''),
        secret=args.secret or client_conf.get('secret', ''),
    )

    ca_cert = args.ca_cert or client_conf.get('ca_cert')

    if not config.username:
        logger.error("No username configured!")
        return 1

    if not config.secret:
        logger.error("No secret configured!")
        return 1

    try:
        return asyncio.run(run_client(config, ca_cert))
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    exit(main())
