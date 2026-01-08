import os
from cryptography.hazmat.primitives import serialization
from utils.key_generation_utils import *
from tls.certificate import *
from  utils.crypto_utils import to_b64, public_key_to_bytes, generate_x25519_keypair

DEFAULT_CIPHERS = ["CHACHA20_POLY1305_SHA256"]
DEFAULT_VERSIONS = ["TLS1.3"]
DEFAULT_KEY_EXCHANGES = ["X25519"]


class HelloMessage:
    def __init__(self, role: str, certificate: Certificate=None, supported_ciphers= None, supported_versions=None, key_exchanges=None):
        """
        Initialize a Hello message for TLS-like handshake.

        Args:
            role (str): "client" or "server"
            supported_ciphers (list): optional list of cipher suites
            supported_versions (list): optional list of protocol versions
            key_exchanges (list): optional list of key exchange algorithms
            certificate (Certificate) : optional certificate of identity
        """
        self.role = role.lower()
        if self.role not in ("client", "server"):
          raise ValueError("role must be 'client' or 'server'")

        self.random_bytes = os.urandom(32)  # 32-byte random nonce
        self.private_key, self.public_key = generate_x25519_keypair()
        self.certificate = certificate  # Can be None for client
        
        # Default values if none provided
        self.supported_ciphers = supported_ciphers or DEFAULT_CIPHERS
        self.supported_versions = supported_versions or DEFAULT_VERSIONS
        self.key_exchanges = key_exchanges or DEFAULT_KEY_EXCHANGES

    def to_dict(self) -> dict:
        """
        Serialize the Hello message to a dictionary ready for network transmission.
        """
        public_bytes = public_key_to_bytes(self.public_key)
        
        d = {
            "type": f"{self.role.capitalize()}Hello",
            f"{self.role}_random": to_b64(self.random_bytes),
            "supported_ciphers": self.supported_ciphers,
            "supported_versions": self.supported_versions,
            "key_exchange_algorithms": self.key_exchanges,
            "public_bytes": to_b64(public_bytes)
        }

        # Only include certificate if it exists
        if self.certificate:
            d["certificate"] = self.certificate.to_dict()

        return d

