# This file simulates the Client
import socket
import threading
import json
from hellomessage_utils import *
from key_generation import *
from concurrency import *

HOST = "127.0.0.1"
PORT = 4444

"""
    As TLS 1.3 is Client-initated the HelloClient will be generated 
    before the Client will connect to the server and send the request
"""

print("Client: ClientHello is being initialized.")

# Build the HelloMessage class for the client
hello_obj = HelloMessage(role="client")

# Get the network-ready dictionary of the ClientHello
client_hello = hello_obj.to_dict()

print("ClientHello generated successfully.")
print("ClientHello message:", client_hello)  # show message contents

# Client connects to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Send ClientHello
    s.sendall(json.dumps(client_hello).encode())
    
    # Receive ServerHello
    data = s.recv(4096)
    server_hello = json.loads(data.decode())

    # Retrieve server certificate
    server_certificate = Certificate.from_dict(server_hello["certificate"])

    # Retrieve Certificate Authority public key
    ca_pub_b64 = server_hello["ca_pub"]
    ca_pub_bytes = base64.b64decode(ca_pub_b64)

    # Recreate Certificate Authority public key
    ca_public_key = ed25519.Ed25519PublicKey.from_public_bytes(ca_pub_bytes)

   # Verify CA signature over server public key
    ca_public_key.verify(
        server_certificate.signature,
        server_certificate.public_key
    )

    # Verify identity matches expected identity
    if server_certificate.identity != "trusted-server":
        raise PermissionError(
            f"Server identity mismatch! Expected 'trusted-server', got '{server_certificate.identity}'"
        )

    print(f"Client: Server certificate verified! Identity: {server_certificate.identity}")
    
    # Compute shared secret
    """
        Compute the shared secret using the ECDH key exchange protocol (X25519).
        This shared secret is derived from the server's ephemeral private key
        and the client's ephemeral public key. It will be used as input to
        the handshake key derivation function (HKDF) for symmetric encryption.

        The ECDH exchange ensures that both client and server derive the same
        secret without transmitting it over the network.

        HKDF takes a raw secret (like from ECDH) and derive one or more 
        cryptographically strong keys.

        I have added a detailed description of ECDH and HKDF in the documentation.
    """
    # From the ServerHello message, retrieve the public bytes and public key
    server_public_bytes = base64.b64decode(server_hello["public_bytes"])
    server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_bytes)
    # Compute the shared secret
    shared_secret = hello_obj.private_key.exchange(server_public_key)
    
    print("Client: Shared secret computed!")

    # Generate the Session keys from AESGCM
    client_random_bytes = hello_obj.random_bytes
    server_random_bytes = base64.b64decode(server_hello["server_random"])

    # The session key is generated using AESGCM, and then all random bytes with the shared secret
    session_key = AESGCM_session_key(client_random_bytes,server_random_bytes,shared_secret)

    # Start listening and sending
    
    print("___________________________________________________")
    print("Client: you can now send and receive messages!")
    # Generate shared event in the threading for when one is being exited
    shutdown_event = threading.Event()

    # Start listener thread
    threading.Thread(target=listen_thread, args=(s, session_key, shutdown_event, "server"),daemon=True).start()

    # Main thread handles sending
    send_thread(s, session_key, shutdown_event)






  



    



    







