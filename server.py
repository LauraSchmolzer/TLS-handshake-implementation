# This file simulates the Server
import socket
import json
from hellomessage_utils import *
from key_generation import *
from concurrency import *

HOST = "127.0.0.1"
PORT = 4444

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    """
        We open a socket for the server such that it can listen to incoming requests
    """
    s.bind((HOST, PORT))
    s.listen(1)
    print("Server: Listening for client...")

    # Here we accept the request and we start with TLS session
    conn, addr = s.accept()
    with conn:
        print("Server: Connected by", addr)

        # Receive ClientHello
        data = conn.recv(4096)
        hello_client = json.loads(data.decode())
        
        # Generate the server Identity keypair
        server_identity = IdentityKeypair()
        pub_bytes = server_identity.to_bytes()

        # Server identity keypair is send to the CA to issue a Certificate
        certificate_authority = CertificateAuthority()  # This is my third party
        server_certificate = certificate_authority.issue_certificate(pub_bytes=pub_bytes, identity="trusted-server")

        ca_pub_bytes = certificate_authority.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Send ca_pub_bytes (or base64 encode it)
        ca_pub_b64 = to_b64(ca_pub_bytes)

        # Build ServerHello
        server_hello_obj = HelloMessage( role="server", certificate=server_certificate)

        # Create ServerHello and add the ca public bytes
        hello_server = server_hello_obj.to_dict()
        hello_server["ca_pub"] = to_b64(certificate_authority.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))

        # We send back the ServerHello to the Client
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
        client_pub_bytes = base64.b64decode(hello_client["x25519_pub"])
  
        client_pub_key = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = server_hello_obj.private_key.exchange(client_pub_key)
        
        print("Server: Shared secret computed!")

        # We generate the Session key from AESGCM

        server_random = server_hello_obj.random_bytes
        client_random = base64.b64decode(hello_client["client_random"])

        session_key = AESGCM_session_key(client_random,server_random,shared_secret)
        
        print("___________________________________________________")
        print("Server: you can now send and receive messages!") 

        # Start listener thread
        threading.Thread(target=listen_thread, args=(conn, session_key, "client"), daemon=True).start()
        # Main thread handles sending
        send_thread(conn, session_key)

    

  
