from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

def to_b64(data: bytes) -> str:
    """Encode bytes as base64 string for JSON/network."""
    return base64.b64encode(data).decode("ascii")

class CertificateAuthority:
    def __init__(self):
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    def issue_certificate(self, pub_bytes, identity="server"):

        signature = self.private.sign(pub_bytes)

        return Certificate(identity, pub_bytes, signature)
    
    def verify(self, certificate):
        self.public.verify(certificate.signature, certificate.public_key)
        return True

class Certificate:
    def __init__(self, identity, public_key, signature):
        self.identity = identity
        self.public_key = public_key
        self.signature = signature
     
    def to_dict(self) -> dict:
        """
            Serialize the certificate to a dictionary ready for network transmission.
        """
        return {
            "identity": self.identity,
            "public_key": to_b64(self.public_key),
            "signature": to_b64(self.signature)
        }

class IdentityKeypair:
    def __init__(self):
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)

    def verify(self, signature: bytes, message: bytes):
        return self.public.verify(signature, message)


