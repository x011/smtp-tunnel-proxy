#!/usr/bin/env python3
"""
Generate self-signed TLS certificates for SMTP tunnel.
Creates server certificate that mimics a real mail server.

Version: 1.3.0
"""

import os
import sys
import argparse
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )


def generate_ca_certificate(
    private_key: rsa.RSAPrivateKey,
    common_name: str = "SMTP Tunnel CA",
    days_valid: int = 3650
) -> x509.Certificate:
    """Generate self-signed CA certificate."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SMTP Tunnel"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return cert


def generate_server_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    server_key: rsa.RSAPrivateKey,
    hostname: str = "mail.example.com",
    days_valid: int = 1095
) -> x509.Certificate:
    """
    Generate server certificate signed by CA.
    Mimics a real mail server certificate.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Mail Services"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    # Subject Alternative Names (important for TLS validation)
    san = x509.SubjectAlternativeName([
        x509.DNSName(hostname),
        x509.DNSName(f"smtp.{hostname.split('.', 1)[-1] if '.' in hostname else hostname}"),
        x509.DNSName("localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    return cert


def save_private_key(key: rsa.RSAPrivateKey, path: str, password: bytes = None):
    """Save private key to PEM file."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )

    with open(path, 'wb') as f:
        f.write(pem)

    # Secure file permissions (owner read-only)
    try:
        os.chmod(path, 0o600)
    except (OSError, AttributeError):
        pass  # Windows doesn't support chmod the same way


def save_certificate(cert: x509.Certificate, path: str):
    """Save certificate to PEM file."""
    pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(path, 'wb') as f:
        f.write(pem)


def main():
    parser = argparse.ArgumentParser(
        description='Generate TLS certificates for SMTP tunnel'
    )
    parser.add_argument(
        '--hostname',
        default='mail.example.com',
        help='Server hostname for certificate (default: mail.example.com)'
    )
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory for certificates (default: current directory)'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=1095,
        help='Certificate validity in days (default: 1095 = 3 years)'
    )
    parser.add_argument(
        '--key-size',
        type=int,
        default=2048,
        help='RSA key size in bits (default: 2048)'
    )

    args = parser.parse_args()

    # Create output directory if needed
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Generating certificates for hostname: {args.hostname}")
    print(f"Key size: {args.key_size} bits")
    print(f"Validity: {args.days} days")
    print()

    # Generate CA
    print("Generating CA private key...")
    ca_key = generate_private_key(args.key_size)

    print("Generating CA certificate...")
    ca_cert = generate_ca_certificate(ca_key, days_valid=args.days * 10)

    # Generate server certificate
    print("Generating server private key...")
    server_key = generate_private_key(args.key_size)

    print("Generating server certificate...")
    server_cert = generate_server_certificate(
        ca_key, ca_cert, server_key,
        hostname=args.hostname,
        days_valid=args.days
    )

    # Save files
    ca_key_path = os.path.join(args.output_dir, 'ca.key')
    ca_cert_path = os.path.join(args.output_dir, 'ca.crt')
    server_key_path = os.path.join(args.output_dir, 'server.key')
    server_cert_path = os.path.join(args.output_dir, 'server.crt')

    print()
    print("Saving files...")

    save_private_key(ca_key, ca_key_path)
    print(f"  CA private key:      {ca_key_path}")

    save_certificate(ca_cert, ca_cert_path)
    print(f"  CA certificate:      {ca_cert_path}")

    save_private_key(server_key, server_key_path)
    print(f"  Server private key:  {server_key_path}")

    save_certificate(server_cert, server_cert_path)
    print(f"  Server certificate:  {server_cert_path}")

    print()
    print("Certificate generation complete!")
    print()
    print("For the server, you need:")
    print(f"  - {server_cert_path}")
    print(f"  - {server_key_path}")
    print()
    print("For the client (to verify server), copy:")
    print(f"  - {ca_cert_path}")
    print()
    print("Or disable certificate verification in the client config (less secure).")


if __name__ == '__main__':
    main()
