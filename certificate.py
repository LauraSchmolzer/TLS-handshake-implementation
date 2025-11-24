from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

def to_b64(data: bytes) -> str:
    """Encode bytes as base64 string for JSON/network."""
    return base64.b64encode(data).decode("ascii")

class CertificateAuthority:
    """
    This is a trusted third party that can vouch for others identities.
    One CA can issue certificates to many clients/servers.

        Purpose:    
            Sign other public keys to certify that they are trustworthy
            Verify certificates signed by itself
    """
    def __init__(self):
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    def issue_certificate(self, pub_bytes, identity):
        # Generate the signature with the keys 
        signature = self.private.sign(pub_bytes)
        # Here we initialize the Certificate
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
            Serialize the certificate to a dictionary ready for network transmission
        """
        return {
            "identity": self.identity,
            "public_key": to_b64(self.public_key),
            "signature": to_b64(self.signature)
        }
    
    def from_dict(d: dict):
        pub_bytes = base64.b64decode(d["public_key"])
        sig_bytes = base64.b64decode(d["signature"])
        identity = d["identity"]
        return Certificate(identity, pub_bytes, sig_bytes)

class IdentityKeypair:
    """
    Purpose:
        Sign messages or handshake transcripts
        Verify signatures (using its public key)
        Identify itself cryptographically
    """
    def __init__(self):
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)

    def verify(self, signature: bytes, message: bytes):
        return self.public.verify(signature, message)
    
    def to_bytes(self) -> bytes:
        """Return raw 32-byte public key for certificates or network use."""
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


