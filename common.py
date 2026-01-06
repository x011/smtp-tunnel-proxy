"""
SMTP Tunnel - Common Protocol and Utilities
Shared components for both client and server.

Version: 1.2.0
"""

import struct
import asyncio
import random
import hashlib
import hmac
import os
import base64
import time
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ============================================================================
# Protocol Constants
# ============================================================================

PROTOCOL_VERSION = 1
MAX_PAYLOAD_SIZE = 65535
NONCE_SIZE = 12
TAG_SIZE = 16

# Message types
class MsgType(IntEnum):
    DATA = 0x01           # Tunnel data
    CONNECT = 0x02        # Open new channel (SOCKS CONNECT)
    CONNECT_OK = 0x03     # Connection established
    CONNECT_FAIL = 0x04   # Connection failed
    CLOSE = 0x05          # Close channel
    KEEPALIVE = 0x06      # Keep connection alive
    KEEPALIVE_ACK = 0x07  # Keepalive response


# ============================================================================
# Tunnel Protocol Message
# ============================================================================

@dataclass
class TunnelMessage:
    """
    Binary protocol for multiplexed tunnel traffic.

    Wire format (before encryption):
    ┌─────────┬────────────┬────────────┬──────────────┬─────────────┐
    │ Version │ Msg Type   │ Channel ID │ Payload Len  │   Payload   │
    │ 1 byte  │  1 byte    │  2 bytes   │  2 bytes     │  variable   │
    └─────────┴────────────┴────────────┴──────────────┴─────────────┘
    """
    msg_type: MsgType
    channel_id: int
    payload: bytes

    HEADER_SIZE = 6  # 1 + 1 + 2 + 2

    def serialize(self) -> bytes:
        """Serialize message to bytes."""
        header = struct.pack(
            '>BBHH',
            PROTOCOL_VERSION,
            self.msg_type,
            self.channel_id,
            len(self.payload)
        )
        return header + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple['TunnelMessage', bytes]:
        """Deserialize message from bytes. Returns (message, remaining_bytes)."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Insufficient data for header")

        version, msg_type, channel_id, payload_len = struct.unpack(
            '>BBHH', data[:cls.HEADER_SIZE]
        )

        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unknown protocol version: {version}")

        total_len = cls.HEADER_SIZE + payload_len
        if len(data) < total_len:
            raise ValueError("Insufficient data for payload")

        payload = data[cls.HEADER_SIZE:total_len]
        remaining = data[total_len:]

        return cls(MsgType(msg_type), channel_id, payload), remaining

    @classmethod
    def data(cls, channel_id: int, data: bytes) -> 'TunnelMessage':
        """Create a DATA message."""
        return cls(MsgType.DATA, channel_id, data)

    @classmethod
    def connect(cls, channel_id: int, host: str, port: int) -> 'TunnelMessage':
        """Create a CONNECT message."""
        # Payload: host_len (1) + host + port (2)
        host_bytes = host.encode('utf-8')
        payload = struct.pack('>B', len(host_bytes)) + host_bytes + struct.pack('>H', port)
        return cls(MsgType.CONNECT, channel_id, payload)

    @classmethod
    def connect_ok(cls, channel_id: int) -> 'TunnelMessage':
        """Create a CONNECT_OK message."""
        return cls(MsgType.CONNECT_OK, channel_id, b'')

    @classmethod
    def connect_fail(cls, channel_id: int, reason: str = '') -> 'TunnelMessage':
        """Create a CONNECT_FAIL message."""
        return cls(MsgType.CONNECT_FAIL, channel_id, reason.encode('utf-8'))

    @classmethod
    def close(cls, channel_id: int) -> 'TunnelMessage':
        """Create a CLOSE message."""
        return cls(MsgType.CLOSE, channel_id, b'')

    @classmethod
    def keepalive(cls) -> 'TunnelMessage':
        """Create a KEEPALIVE message."""
        return cls(MsgType.KEEPALIVE, 0, b'')

    @classmethod
    def keepalive_ack(cls) -> 'TunnelMessage':
        """Create a KEEPALIVE_ACK message."""
        return cls(MsgType.KEEPALIVE_ACK, 0, b'')

    def parse_connect(self) -> Tuple[str, int]:
        """Parse CONNECT payload to get host and port."""
        if self.msg_type != MsgType.CONNECT:
            raise ValueError("Not a CONNECT message")
        host_len = self.payload[0]
        host = self.payload[1:1+host_len].decode('utf-8')
        port = struct.unpack('>H', self.payload[1+host_len:3+host_len])[0]
        return host, port


# ============================================================================
# Cryptography
# ============================================================================

class TunnelCrypto:
    """
    Handles encryption/decryption of tunnel messages.
    Uses ChaCha20-Poly1305 for authenticated encryption.
    Key derivation from pre-shared secret using HKDF.
    """

    def __init__(self, secret: str, is_server: bool = False):
        """
        Initialize crypto with pre-shared secret.

        Args:
            secret: Pre-shared key string
            is_server: True for server, False for client
        """
        self.secret = secret.encode('utf-8')
        self.is_server = is_server

        # Derive separate keys for client->server and server->client
        self._derive_keys()

        # Sequence numbers for nonce generation (prevent replay)
        self.send_seq = 0
        self.recv_seq = 0

    def _derive_keys(self):
        """Derive encryption keys from secret using HKDF."""
        # Derive master key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for each direction
            salt=b'smtp-tunnel-v1',
            info=b'tunnel-keys',
        )
        key_material = hkdf.derive(self.secret)

        # Split into client->server and server->client keys
        c2s_key = key_material[:32]
        s2c_key = key_material[32:]

        if self.is_server:
            self.send_key = ChaCha20Poly1305(s2c_key)
            self.recv_key = ChaCha20Poly1305(c2s_key)
        else:
            self.send_key = ChaCha20Poly1305(c2s_key)
            self.recv_key = ChaCha20Poly1305(s2c_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with authenticated encryption.
        Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        # Generate nonce from sequence number + random
        nonce = struct.pack('>Q', self.send_seq) + os.urandom(4)
        self.send_seq += 1

        ciphertext = self.send_key.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt and verify data.
        Input: nonce (12 bytes) + ciphertext + tag (16 bytes)
        Returns: plaintext
        """
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Data too short")

        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]

        plaintext = self.recv_key.decrypt(nonce, ciphertext, None)
        self.recv_seq += 1

        return plaintext

    def generate_auth_token(self, timestamp: int, username: str = None) -> str:
        """
        Generate authentication token for SMTP AUTH.
        Uses HMAC-SHA256 with timestamp to prevent replay.

        Args:
            timestamp: Unix timestamp
            username: Optional username (for multi-user mode)

        Returns:
            Base64 encoded token
        """
        if username:
            message = f"smtp-tunnel-auth:{username}:{timestamp}".encode()
            mac = hmac.new(self.secret, message, hashlib.sha256).digest()
            # Format: base64(username:timestamp:mac)
            token = f"{username}:{timestamp}:{base64.b64encode(mac).decode()}"
        else:
            # Legacy format for backward compatibility
            message = f"smtp-tunnel-auth:{timestamp}".encode()
            mac = hmac.new(self.secret, message, hashlib.sha256).digest()
            # Format: base64(timestamp:mac)
            token = f"{timestamp}:{base64.b64encode(mac).decode()}"
        return base64.b64encode(token.encode()).decode()

    def verify_auth_token(self, token: str, max_age: int = 300) -> Tuple[bool, Optional[str]]:
        """
        Verify authentication token.

        Args:
            token: Base64 encoded auth token
            max_age: Maximum age in seconds (default 5 minutes)

        Returns:
            Tuple of (is_valid, username) - username is None for legacy tokens
        """
        try:
            decoded = base64.b64decode(token).decode()
            parts = decoded.split(':')

            if len(parts) == 3:
                # New format: username:timestamp:mac
                username, timestamp_str, mac_b64 = parts
                timestamp = int(timestamp_str)
            elif len(parts) == 2:
                # Legacy format: timestamp:mac
                username = None
                timestamp_str, mac_b64 = parts
                timestamp = int(timestamp_str)
            else:
                return False, None

            # Check timestamp freshness
            now = int(time.time())
            if abs(now - timestamp) > max_age:
                return False, None

            # Verify HMAC
            expected_token = self.generate_auth_token(timestamp, username)
            if hmac.compare_digest(token, expected_token):
                return True, username
            return False, None
        except Exception:
            return False, None

    @staticmethod
    def verify_auth_token_multi_user(token: str, users: dict, max_age: int = 300) -> Tuple[bool, Optional[str]]:
        """
        Verify authentication token against multiple users.

        Args:
            token: Base64 encoded auth token
            users: Dict of {username: UserConfig} or {username: secret_string}
            max_age: Maximum age in seconds (default 5 minutes)

        Returns:
            Tuple of (is_valid, username)
        """
        try:
            decoded = base64.b64decode(token).decode()
            parts = decoded.split(':')

            if len(parts) != 3:
                return False, None

            username, timestamp_str, mac_b64 = parts
            timestamp = int(timestamp_str)

            # Check timestamp freshness
            now = int(time.time())
            if abs(now - timestamp) > max_age:
                return False, None

            # Look up user
            if username not in users:
                return False, None

            user_data = users[username]
            if isinstance(user_data, UserConfig):
                secret = user_data.secret
            elif isinstance(user_data, dict):
                secret = user_data.get('secret', '')
            else:
                secret = str(user_data)

            # Verify HMAC with user's secret
            crypto = TunnelCrypto(secret)
            expected_token = crypto.generate_auth_token(timestamp, username)
            if hmac.compare_digest(token, expected_token):
                return True, username
            return False, None
        except Exception:
            return False, None


# ============================================================================
# Traffic Shaping
# ============================================================================

class TrafficShaper:
    """
    Implements DPI evasion through traffic shaping:
    - Random delays between messages
    - Padding to standard sizes
    - Occasional dummy messages
    """

    # Standard padding sizes (common email attachment sizes)
    PAD_SIZES = [4096, 8192, 16384, 32768]

    def __init__(
        self,
        min_delay_ms: int = 50,
        max_delay_ms: int = 500,
        dummy_probability: float = 0.1
    ):
        """
        Initialize traffic shaper.

        Args:
            min_delay_ms: Minimum delay between messages
            max_delay_ms: Maximum delay between messages
            dummy_probability: Probability of sending dummy message
        """
        self.min_delay_ms = min_delay_ms
        self.max_delay_ms = max_delay_ms
        self.dummy_probability = dummy_probability

    async def delay(self):
        """Add random delay to simulate human behavior."""
        delay_ms = random.randint(self.min_delay_ms, self.max_delay_ms)
        await asyncio.sleep(delay_ms / 1000.0)

    def pad_data(self, data: bytes) -> bytes:
        """
        Pad data to next standard size.
        Padding format: data_length (2 bytes) + data + random_padding
        """
        data_len = len(data)

        # Find next standard size (need space for 2-byte length prefix)
        total_needed = data_len + 2
        target_size = self.PAD_SIZES[-1]  # Default to largest
        for size in self.PAD_SIZES:
            if total_needed <= size:
                target_size = size
                break

        padding_len = target_size - total_needed
        padding = os.urandom(padding_len) if padding_len > 0 else b''

        # Format: length prefix + data + padding
        return struct.pack('>H', data_len) + data + padding

    @staticmethod
    def unpad_data(padded_data: bytes) -> bytes:
        """Remove padding from data."""
        if len(padded_data) < 2:
            return padded_data

        # Read data length from first 2 bytes
        data_len = struct.unpack('>H', padded_data[:2])[0]

        # Extract data (skip 2-byte length prefix)
        return padded_data[2:2 + data_len]

    def should_send_dummy(self) -> bool:
        """Determine if we should send a dummy message."""
        return random.random() < self.dummy_probability

    def generate_dummy_data(self, min_size: int = 100, max_size: int = 1000) -> bytes:
        """Generate random dummy data."""
        size = random.randint(min_size, max_size)
        return os.urandom(size)


# ============================================================================
# SMTP Message Generation
# ============================================================================

class SMTPMessageGenerator:
    """
    Generates realistic-looking SMTP messages to wrap tunnel data.
    """

    # Realistic subject lines
    SUBJECTS = [
        "Re: Your order #{order_id} has shipped",
        "Invoice attached - Account #{account_id}",
        "Meeting notes from {date}",
        "Fwd: Document you requested",
        "Weekly report - Week {week}",
        "RE: Quick question about the project",
        "Updated files attached",
        "Confirmation: Your appointment on {date}",
        "Receipt for your purchase",
        "Action required: Please review",
        "FW: Important update",
        "Re: Follow up on our conversation",
    ]

    # Sender domains (common providers)
    DOMAINS = [
        "gmail.com", "outlook.com", "yahoo.com", "protonmail.com",
        "icloud.com", "mail.com", "hotmail.com"
    ]

    # First names for realistic From headers
    FIRST_NAMES = [
        "John", "Jane", "Michael", "Sarah", "David", "Emily",
        "James", "Emma", "Robert", "Olivia", "William", "Sophia"
    ]

    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
        "Miller", "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson"
    ]

    # Text bodies for the plain text part
    BODY_TEMPLATES = [
        "Please find the attached document.\n\nBest regards",
        "As discussed, here are the files.\n\nThanks",
        "Attached is the information you requested.\n\nRegards",
        "Please review the attached.\n\nThank you",
        "Here's the document.\n\nBest",
    ]

    def __init__(self, from_domain: str = "example.com", to_domain: str = "example.org"):
        """
        Initialize message generator.

        Args:
            from_domain: Domain for sender addresses
            to_domain: Domain for recipient addresses
        """
        self.from_domain = from_domain
        self.to_domain = to_domain
        self._message_counter = 0

    def generate_message_id(self) -> str:
        """Generate a realistic Message-ID."""
        random_part = os.urandom(8).hex()
        timestamp = int(time.time() * 1000) % 1000000
        return f"<{random_part}.{timestamp}@{self.from_domain}>"

    def generate_subject(self) -> str:
        """Generate a realistic subject line."""
        template = random.choice(self.SUBJECTS)
        now = datetime.now()
        return template.format(
            order_id=random.randint(10000, 99999),
            account_id=random.randint(1000, 9999),
            date=now.strftime("%B %d"),
            week=now.isocalendar()[1]
        )

    def generate_sender(self) -> Tuple[str, str]:
        """Generate realistic From name and address."""
        first = random.choice(self.FIRST_NAMES)
        last = random.choice(self.LAST_NAMES)
        name = f"{first} {last}"

        # Generate email variations
        email_styles = [
            f"{first.lower()}.{last.lower()}",
            f"{first.lower()}{last.lower()}",
            f"{first[0].lower()}{last.lower()}",
            f"{first.lower()}{random.randint(1, 99)}",
        ]
        email = f"{random.choice(email_styles)}@{random.choice(self.DOMAINS)}"

        return name, email

    def generate_recipient(self) -> Tuple[str, str]:
        """Generate realistic To address."""
        first = random.choice(self.FIRST_NAMES)
        last = random.choice(self.LAST_NAMES)
        name = f"{first} {last}"
        email = f"{first.lower()}.{last.lower()}@{self.to_domain}"
        return name, email

    def generate_boundary(self) -> str:
        """Generate MIME boundary."""
        return f"----=_Part_{os.urandom(6).hex()}"

    def wrap_tunnel_data(self, tunnel_data: bytes, filename: str = "document.dat") -> Tuple[str, str, str, str]:
        """
        Wrap tunnel data in a realistic MIME email message.

        Returns:
            Tuple of (from_addr, to_addr, subject, message_body)
        """
        from_name, from_addr = self.generate_sender()
        to_name, to_addr = self.generate_recipient()
        subject = self.generate_subject()
        message_id = self.generate_message_id()
        boundary = self.generate_boundary()

        # Current date in RFC 2822 format
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a, %d %b %Y %H:%M:%S %z")

        # Base64 encode tunnel data (76 char line width per RFC 2045)
        b64_data = base64.b64encode(tunnel_data).decode('ascii')
        b64_lines = [b64_data[i:i+76] for i in range(0, len(b64_data), 76)]
        b64_formatted = '\r\n'.join(b64_lines)

        # Build MIME message
        body_text = random.choice(self.BODY_TEMPLATES)

        message = f"""From: {from_name} <{from_addr}>
To: {to_name} <{to_addr}>
Subject: {subject}
Date: {date_str}
Message-ID: {message_id}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

{body_text}

--{boundary}
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="{filename}"

{b64_formatted}
--{boundary}--"""

        # Convert to CRLF line endings
        message = message.replace('\n', '\r\n')

        return from_addr, to_addr, subject, message

    def extract_tunnel_data(self, message: str) -> Optional[bytes]:
        """
        Extract tunnel data from MIME message.

        Returns:
            Extracted binary data or None if not found
        """
        try:
            # Find base64 attachment section
            # Look for Content-Transfer-Encoding: base64 followed by data
            lines = message.replace('\r\n', '\n').split('\n')
            in_attachment = False
            b64_lines = []

            for i, line in enumerate(lines):
                if 'Content-Transfer-Encoding: base64' in line:
                    in_attachment = True
                    continue

                if in_attachment:
                    if line.startswith('--'):
                        break
                    if line.strip():
                        b64_lines.append(line.strip())

            if b64_lines:
                b64_data = ''.join(b64_lines)
                return base64.b64decode(b64_data)

            return None
        except Exception:
            return None


# ============================================================================
# SMTP State Machine
# ============================================================================

class SMTPState:
    """SMTP session state machine for protocol compliance."""

    INITIAL = 'initial'
    GREETED = 'greeted'
    TLS_STARTED = 'tls_started'
    AUTHENTICATED = 'authenticated'
    MAIL_FROM = 'mail_from'
    RCPT_TO = 'rcpt_to'
    DATA = 'data'
    QUIT = 'quit'

    # SMTP Response codes
    READY = 220
    CLOSING = 221
    AUTH_SUCCESS = 235
    OK = 250
    START_INPUT = 354
    AUTH_CONTINUE = 334
    TEMP_FAIL = 421
    SYNTAX_ERROR = 500
    COMMAND_UNRECOGNIZED = 502
    BAD_SEQUENCE = 503
    AUTH_REQUIRED = 530
    AUTH_FAILED = 535


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class UserConfig:
    """Per-user configuration."""
    username: str
    secret: str
    whitelist: List[str] = None  # Per-user IP whitelist (empty = allow all)
    logging: bool = True  # Per-user logging

    def __post_init__(self):
        if self.whitelist is None:
            self.whitelist = []


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = '0.0.0.0'
    port: int = 587
    hostname: str = 'mail.example.com'
    cert_file: str = 'server.crt'
    key_file: str = 'server.key'
    users_file: str = 'users.yaml'  # Path to users configuration
    log_users: bool = True  # Global logging setting (can be overridden per-user)


class IPWhitelist:
    """
    IP address whitelist with CIDR notation support.

    Usage:
        whitelist = IPWhitelist(['192.168.1.0/24', '10.0.0.1'])
        if whitelist.is_allowed('192.168.1.100'):
            # allow connection
    """

    def __init__(self, entries: List[str] = None):
        """
        Initialize whitelist.

        Args:
            entries: List of IP addresses or CIDR ranges
                    Empty list = allow all connections
        """
        self.entries = entries or []
        self._parsed = []
        self._parse_entries()

    def _parse_entries(self):
        """Parse IP entries into (network, mask) tuples."""
        import ipaddress

        for entry in self.entries:
            try:
                # Try parsing as network (CIDR notation)
                if '/' in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    self._parsed.append(network)
                else:
                    # Single IP address
                    addr = ipaddress.ip_address(entry)
                    # Convert to /32 (IPv4) or /128 (IPv6) network
                    if addr.version == 4:
                        network = ipaddress.ip_network(f"{entry}/32")
                    else:
                        network = ipaddress.ip_network(f"{entry}/128")
                    self._parsed.append(network)
            except ValueError:
                # Invalid entry, skip it
                pass

    def is_allowed(self, ip: str) -> bool:
        """
        Check if an IP address is allowed.

        Args:
            ip: IP address to check

        Returns:
            True if allowed (empty whitelist = allow all),
            False if not in whitelist
        """
        # Empty whitelist means allow all
        if not self.entries:
            return True

        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)

            for network in self._parsed:
                if addr in network:
                    return True

            return False
        except ValueError:
            # Invalid IP address
            return False

    def __bool__(self):
        """Return True if whitelist has entries (is active)."""
        return bool(self.entries)


@dataclass
class ClientConfig:
    """Client configuration."""
    server_host: str = 'localhost'
    server_port: int = 587
    socks_port: int = 1080
    socks_host: str = '127.0.0.1'
    username: str = ''  # Username for multi-user auth
    secret: str = ''


@dataclass
class StealthConfig:
    """Stealth/traffic shaping configuration."""
    min_delay_ms: int = 50
    max_delay_ms: int = 500
    pad_to_sizes: List[int] = None
    dummy_message_probability: float = 0.1

    def __post_init__(self):
        if self.pad_to_sizes is None:
            self.pad_to_sizes = [4096, 8192, 16384]


def load_config(path: str) -> dict:
    """Load configuration from YAML file."""
    import yaml
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}


def load_users(path: str) -> Dict[str, UserConfig]:
    """
    Load users from YAML file.

    Args:
        path: Path to users.yaml

    Returns:
        Dict of {username: UserConfig}
    """
    import yaml

    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

    users = {}
    users_data = data.get('users', {})

    for username, user_data in users_data.items():
        if isinstance(user_data, dict):
            users[username] = UserConfig(
                username=username,
                secret=user_data.get('secret', ''),
                whitelist=user_data.get('whitelist', []),
                logging=user_data.get('logging', True)
            )
        elif isinstance(user_data, str):
            # Simple format: username: secret
            users[username] = UserConfig(
                username=username,
                secret=user_data,
                whitelist=[],
                logging=True
            )

    return users


def save_users(path: str, users: Dict[str, UserConfig]):
    """
    Save users to YAML file.

    Args:
        path: Path to users.yaml
        users: Dict of {username: UserConfig}
    """
    import yaml

    data = {'users': {}}
    for username, user in users.items():
        user_data = {
            'secret': user.secret,
        }
        if user.whitelist:
            user_data['whitelist'] = user.whitelist
        if not user.logging:
            user_data['logging'] = False
        data['users'][username] = user_data

    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# ============================================================================
# Utilities
# ============================================================================

class FrameBuffer:
    """
    Buffer for accumulating and parsing tunnel messages.
    Handles partial reads and message boundaries.
    """

    def __init__(self):
        self.buffer = b''

    def append(self, data: bytes):
        """Add data to buffer."""
        self.buffer += data

    def get_messages(self) -> List[TunnelMessage]:
        """
        Extract complete messages from buffer.
        Returns list of messages, updates buffer to contain remainder.
        """
        messages = []

        while len(self.buffer) >= TunnelMessage.HEADER_SIZE:
            try:
                # Peek at payload length
                _, _, _, payload_len = struct.unpack(
                    '>BBHH', self.buffer[:TunnelMessage.HEADER_SIZE]
                )
                total_len = TunnelMessage.HEADER_SIZE + payload_len

                if len(self.buffer) < total_len:
                    break  # Wait for more data

                msg, remaining = TunnelMessage.deserialize(self.buffer)
                messages.append(msg)
                self.buffer = remaining

            except ValueError:
                break

        return messages

    def clear(self):
        """Clear the buffer."""
        self.buffer = b''


class AsyncQueue:
    """Simple async queue wrapper for message passing."""

    def __init__(self, maxsize: int = 0):
        self._queue = asyncio.Queue(maxsize=maxsize)

    async def put(self, item):
        await self._queue.put(item)

    async def get(self):
        return await self._queue.get()

    def put_nowait(self, item):
        self._queue.put_nowait(item)

    def get_nowait(self):
        return self._queue.get_nowait()

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()
