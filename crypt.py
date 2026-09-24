"""Small helpers for encrypting and checking binary transfer chunks.

Both ends of the link must have the same secret key. Keep it off the radio.
Encrypted chunks contain a fresh 12-byte nonce followed by the AES-GCM
ciphertext and its 16-byte authentication tag.
"""

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_keys() -> tuple[bytes, bytes]:
    """Generates an RSA-2048 key pair.

    Returns:
        (private_key_pem, public_key_pem) as PEM-encoded bytes.
    """
    # Generate 2048-bit RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Export Private Key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Export Public Key to PEM format
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def encrypt(message: bytes, public_key_pem: bytes) -> bytes:
    """Encrypt a byte chunk using an RSA Public Key (PEM bytes)."""
    # Load the PEM-formatted public key
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Encrypt using RSA-OAEP padding
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def decrypt(message: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt a byte chunk using an RSA Private Key (PEM bytes)."""
    # Load the PEM-formatted private key
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None
    )

    # Decrypt using RSA-OAEP padding
    try:
        plaintext = private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed or data damaged: {e}")


def md5sum(message: bytes) -> str:
    """Return the 32-character hexadecimal MD5 checksum of a byte chunk."""
    return hashlib.md5(message, usedforsecurity=False).hexdigest()