from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from hellomessage_utils import *


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
