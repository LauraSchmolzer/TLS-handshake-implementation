import socket, threading,json,sys,time

from tls.certificate import Certificate
from tls.utils.crypto_utils import from_b64, recreate_CerificateAuthority_public_key

from fsm.tls_context import TLSContext

class BaseState:
    def run(self, ctx: TLSContext):
        raise NotImplementedError 

class ClosedState(BaseState):
    def run(self, ctx: TLSContext):
        print(f"{ctx.role} connection closed.")
        return self  # terminal state
    

# This is the initial state of the server
class OpenListeningState(BaseState):
    def run(self, ctx: TLSContext):
        ctx.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx.sock.bind((ctx.host, ctx.port))
        ctx.sock.listen(1)
        print(f"Listening on {ctx.host}:{ctx.port}")
        return ListeningState()

# Server listeing for incoming hello messages
class ListeningState(BaseState):
    def run(self, ctx: TLSContext):
        try:
            ctx.conn, ctx.addr = ctx.sock.accept()
            ctx.active_socket = ctx.conn  
            print(f"Client connected by {ctx.addr}")
            return ReceiveHelloState()
        except KeyboardInterrupt:
            print("\n[INFO] Server interrupted. Shutting down...")
            ctx.sock.close()
            return ClosedState()


class ReceiveHelloState(BaseState):
    def run(self, ctx: TLSContext):
        # Use the unified active socket for send/recv
        sock = ctx.active_socket
      
        # Receive data
        data = sock.recv(4096)
        if not data:
            raise ConnectionError(f"{ctx.role} received no data")

        # Decode JSON
        ctx.hello_peer_dict = json.loads(data.decode())
       
        # Decide next state
        if ctx.role == "server":
            return GenerateCertState()
        else:
            return VerifyCertState()


class GenerateCertState(BaseState):
    def run(self, ctx: TLSContext):
        ctx.compute_cert()
        return GenerateHelloState()

# This is the initial state of the Client
class GenerateHelloState(BaseState):
    def run(self, ctx: TLSContext):
        ctx.generate_hello()
        return SentHelloState() # Both go to Sent state

class SentHelloState(BaseState):
    def run(self, ctx: TLSContext):
        if ctx.role == "server":
            # Send back the ServerHello to the Client
            ctx.conn.sendall(json.dumps(ctx.hello_dict).encode())
            return KeyGenState()
        else:
            # Client: try connecting up to 3 times
            ctx.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            for attempt in range(3):
                try:
                    ctx.sock.connect((ctx.host, ctx.port))
                    ctx.active_socket = ctx.sock  # store active socket
                    print(f"[INFO] Connected to {ctx.host}:{ctx.port}")
                    break
                except ConnectionRefusedError:
                    print(f"[INFO] Attempt {attempt+1}: Connection refused, retrying...")
                    time.sleep(1)
            else:
                print("[ERROR] Failed to connect after 3 attempts.")
                return ClosedState()

            # Send ClientHello
            ctx.active_socket.sendall(json.dumps(ctx.hello_dict).encode())
            return ReceiveHelloState()
        


class VerifyCertState(BaseState):
    def run(self, ctx: TLSContext):
        # Retrieve server certificate
        hello_peer_dict = ctx.hello_peer_dict
        server_certificate = Certificate.from_dict(hello_peer_dict["certificate"])

        # Retrieve Certificate Authority public key
        ca_pub_b64 = hello_peer_dict["ca_pub"]
        ca_pub_bytes = from_b64(ca_pub_b64)

        # Recreate Certificate Authority public key
        ca_public_key = recreate_CerificateAuthority_public_key(ca_pub_bytes)

    # Verify CA signature over server public key
        ca_public_key.verify(
            server_certificate.signature,
            server_certificate.public_key
        )

        # Verify identity matches expected identity
        if server_certificate.identity != "trusted-server":
            print("[ERROR] Server identity mismatch")
            return ClosedState()

        print(f"Client: Server certificate verified! Identity: {server_certificate.identity}")
        return KeyGenState()
        


class KeyGenState(BaseState):
    def run(self, ctx):
        ctx.compute_keys()
        return OpenConnectionState()

class OpenConnectionState(BaseState):
    def run(self, ctx: TLSContext):
        print(f"{ctx.role} ready to send and receive messages!")
        ctx.start_communication()

        ctx.shutdown_event.wait()
        return ClosedState()




