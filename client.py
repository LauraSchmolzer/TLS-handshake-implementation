# This file simulates the Client
import socket
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

# Get the network-ready dictionary
hello_client = hello_obj.to_dict()

print("ClientHello generated successfully.")
print("ClientHello message:", hello_client)  # show message contents

# Now the Client connects to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Send ClientHello
    s.sendall(json.dumps(hello_client).encode())
    
    # Receive ServerHello
    data = s.recv(4096)
    hello_server = json.loads(data.decode())

    # Retrieve server certificate
    server_certificate = Certificate.from_dict(hello_server["certificate"])

    # Retrieve Certificate Authority public key
    ca_pub_b64 = hello_server["ca_pub"]
    ca_pub_bytes = base64.b64decode(ca_pub_b64)

    # Recreate Certificate Authority public key
    ca_public_key = ed25519.Ed25519PublicKey.from_public_bytes(ca_pub_bytes)

    # Verify server certificate
    ca_public_key.verify(
        server_certificate.signature,
        server_certificate.public_key
    )

    print(f"Client: Server certificate verified! Identity: {hello_server['certificate']['identity']}")
    
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
    server_pub_bytes = base64.b64decode(hello_server["x25519_pub"])

    server_pub_key = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret = hello_obj.private_key.exchange(server_pub_key)
    
    print("Client: Shared secret computed!")

    # We generate the Session key from AESGCM

    client_random = hello_obj.random_bytes
    server_random = base64.b64decode(hello_server["server_random"])

    session_key = AESGCM_session_key(client_random,server_random,shared_secret)
    
    print("___________________________________________________")
    print("Client: you can now send and receive messages!")
    # Start listener thread
    threading.Thread(target=listen_thread, args=(s, session_key, "server"),daemon=True).start()

    # Main thread handles sending
    send_thread(s, session_key)






  



    



    







