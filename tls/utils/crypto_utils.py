import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_x25519_keypair():
    """"
        Here we generate a new X25519 keypair
        X25519 is a Diffie-Hellman key exchange function built on Curve25519
        The library handles the secure randomness, key clamping, and all elliptic-curve math internally
        
        Returns:
        (private_key, public_key):
            private_key : X25519PrivateKey
            public_key  : X25519PublicKey
    """
    print("Generating X25519 keypair...")
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def AESGCM_session_key(client_random: bytes,server_random: bytes ,shared_secret: bytes) -> bytes:
    """"
        Here we derive AESGCM session keyy
        
        Returns:
        session_key:
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit session key
        salt=client_random + server_random,
        info=b"handshake data"
    )
    session_key = hkdf.derive(shared_secret)
    print("Client: Session key derived via HKDF!")
    return session_key

def recreate_CerificateAuthority_public_key(ca_public_bytes: bytes):
    """
        Recreate Certificate Authority public key
    """
    return ed25519.Ed25519PublicKey.from_public_bytes(ca_public_bytes)

def recreate_HelloMessage_public_key(server_public_bytes: bytes):
    """
        Recreate HelloMessage public key
    """
    return x25519.X25519PublicKey.from_public_bytes(server_public_bytes)



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


