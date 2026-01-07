from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import base64

"""
    AES-GCM is an AEAD cipher (Authenticated Encryption with Associated Data).
    
    AES (Advanced Encryption Standard) provides the encryption,
    GCM (Galois/Counter Mode) provides message integrity and authentication (MAC)
    
    Together, this ensures both confidentiality and authenticity of messages.

"""

def encrypt_message(session_key: bytes, plaintext: str, nonce: bytes) -> bytes:
    """
    Encrypt a plaintext message using AES-GCM.
    
    Args:
        session_key: symmetric key derived from HKDF
        plaintext: message to encrypt
        nonce: 12-byte unique nonce for this message
    Returns:
        ciphertext: encrypted bytes
    """
    aead = AESGCM(session_key)
    return aead.encrypt(nonce, plaintext.encode(), None)

def decrypt_message(session_key: bytes, ciphertext: bytes, nonce: bytes) -> str:
    """
    Decrypt a ciphertext message using AES-GCM.
    
    Args:
        session_key: symmetric key derived from HKDF
        ciphertext: encrypted bytes
        nonce: same nonce used for encryption
    Returns:
        plaintext: decrypted string
    """
    aead = AESGCM(session_key)
    return aead.decrypt(nonce, ciphertext, None).decode()



"""
    Helper functions to convert between string and base64 bytes for network transmission
"""

# Encode bytes as base64 string for JSON/network
def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

# Decode bytes as base64 string from JSON/network
def from_b64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

# Convert an Ed25519 public key to raw bytes.
def public_key_to_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
