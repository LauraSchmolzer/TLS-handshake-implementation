import os
from cryptography.hazmat.primitives.asymmetric import x25519


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
