from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

def to_b64(data: bytes) -> str:
    """Encode bytes as base64 string for JSON/network."""
    return base64.b64encode(data).decode("ascii")

class CertificateAuthority:
    """
        Represents a trusted third-party Certificate Authority (CA).

        Purpose:
        Responsible for binding an identity to a public key. 
        It does this by signing the public key, forming a 
        certificate. Any client who trusts the CA's public key can verify 
        certificates issued by it.

        Responsibilities:
        - Sign identity public keys to create certificates
        - Verify certificates it previously issued
        - Act as a trust anchor in TLS system
    """
    def __init__(self):
        self.private = ed25519.Ed25519PrivateKey.generate() # This will essentially sign the subject’s public key
        self.public = self.private.public_key() # This can be distributed to all clients

    def issue_certificate(self, pub_bytes, identity):
        # Generate the signature: CA's private key over certificate public key
        signature = self.private.sign(pub_bytes)
        # Here we initialize the Certificate
        return Certificate(identity, pub_bytes, signature)
    
    def verify(self, certificate):
        self.public.verify(certificate.signature, certificate.public_key)
        return True

class Certificate:
    """
        Object of the Certificate

        Args:
            identity (str): identity of the Certificate
            public key (bytes): The Ed25519 public key of the certificate owner. 
                                This is the key the CA is certifying
            signature (bytes): A signature produced by the CA's private key over `public_key`.
    """
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
        """Reconstruct a certificate from JSON-safe dict."""
        pub_bytes = base64.b64decode(d["public_key"])
        sig_bytes = base64.b64decode(d["signature"])
        identity = d["identity"]
        return Certificate(identity, pub_bytes, sig_bytes)

class IdentityKeypair:
    """
    Represents a long-term Ed25519 identity keypair, which 
    represents the cryptographic identity of an endpoint

    Purpose:
      - Signing handshake transcripts (authenticating the endpoint)
      - Proving ownership of a certificate
      - Verifying signatures from the remote peer

    """
    def __init__(self):
        # Generate a long-term Ed25519 identity keypair
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


