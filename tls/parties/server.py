# This file simulates the Server
import socket
import threading
import json
from tls.hellomessage import *
from utils.key_generation_utils import *
from utils.concurrency_utils import *

HOST = "127.0.0.1"
PORT = 4444

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    """
        We open a socket for the server such that it can listen to incoming requests
    """
    s.bind((HOST, PORT))
    s.listen(1)
    print("Server: Listening for client...")

    # Accept the request and we start with TLS session
    try: 
        conn, addr = s.accept()
    except KeyboardInterrupt:
        print("\n[INFO] Server interrupted. Shutting down...")
        s.close()
        exit(0)
    with conn:
        print("Server: Connected by", addr)

        # Receive ClientHello
        data = conn.recv(4096)
        client_hello = json.loads(data.decode())
        
        # Generate the server Identity keypair
        server_identity = IdentityKeypair()
        identity_public_key_bytes = server_identity.to_bytes()

        # Use Certificate Authority to issue a certificate for the server
        certificate_authority = CertificateAuthority()  # This is the trusted third party that signs the certificate
        server_certificate = certificate_authority.issue_certificate(
            public_key_bytes=identity_public_key_bytes, 
            identity="trusted-server")

        # Retrieve the CA public key bytes and encode for the network
        ca_public_key_bytes = certificate_authority.to_bytes()
        ca_public_key_b64 = to_b64(ca_public_key_bytes)

        # Build ServerHello with certificare
        server_hello_obj = HelloMessage( role="server", certificate=server_certificate)
        hello_server = server_hello_obj.to_dict()

        # Add the public key to the message to send over the network 
        hello_server["ca_pub"] = ca_public_key_b64

        # Send back the ServerHello to the Client
        conn.sendall(json.dumps(hello_server).encode())
        
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
        client_public_bytes = base64.b64decode(client_hello["public_bytes"])
  
        client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_bytes)
        shared_secret = server_hello_obj.private_key.exchange(client_public_key)
        
        print("Server: Shared secret computed!")

        # Generate the Session key from AESGCM
        server_random_bytes = server_hello_obj.random_bytes
        client_random_bytes = base64.b64decode(client_hello["client_random"])

        # The session key is generated using AESGCM, and then all random bytes with the shared secret
        session_key = AESGCM_session_key(client_random_bytes,server_random_bytes,shared_secret)
        
        print("___________________________________________________")
        print("Server: you can now send and receive messages!") 
        # Shared event in the threading for when one is being exited
        shutdown_event = threading.Event()

        # Start listener thread
        threading.Thread(target=listen_thread, args=(conn, session_key,shutdown_event, "client"), daemon=True).start()

        # Main thread handles sending
        send_thread(conn, session_key,shutdown_event)

    

  
