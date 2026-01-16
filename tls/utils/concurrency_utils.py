import socket
from .crypto_utils import encrypt_message, decrypt_message
from cryptography.exceptions import InvalidTag

"""
    Threaded send/receive functions for a TLS-like encrypted connection.
    In this way we have one thread listening and one thread sending; concurrency.

    Modules:
    socket      - for TCP connections
    crypto_utils - for encrypt_message / decrypt_message
    threading   - for managing shutdown events across threads
"""



def listen_thread(conn, session_key, shutdown_event,non_self):
    """
    Thread function to continuously receive messages from the connection.

    Args:
        conn (socket.socket): Active socket connection to peer.
        session_key (bytes): Session key for message decryption.
        shutdown_event (threading.Event): Event to signal threads to stop.
        peer_name (str): Identifier for the peer (e.g., 'Client' or 'Server').
    """

    counter = 0
    try:
        # Check if it is signalled that thread is shut down
        while not shutdown_event.is_set():
            try:
                # Wait for incoming data from the connection
                data = conn.recv(4096)
            except (OSError, ConnectionResetError):
                # Socket may be closed from the other side; exit the loop safely
                print("Socket closed from other side.")
                break

            if not data:
                # Conenction is closed gracefully by self or peer
                print(f"Connection closed.")
                break

            # Slit the received data into nonce (12 bytes) and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]

            try:
                # Attempt to decrypt the received message
                plaintext = decrypt_message(session_key, ciphertext, nonce)

            except InvalidTag:
                # Ignore decryption failures if connection is closing
                print("Warning: InvalidTag detected, breaking listen loop. ")
                break

            if plaintext.lower() == "exit":
                print(f"{non_self} closed the connection.")
                # Signal the connection is being shut down: can be checked by other thread
                shutdown_event.set()
                break
            else:
                print(f"\nReceived message: {plaintext}")
            counter += 1
    finally:
        # Ensure shutdown and close the socket
        shutdown_event.set()
        try: conn.shutdown(socket.SHUT_RDWR) # Stop further sends and receives
        except: pass
        try: conn.close() # Close connection
        except: pass

def send_thread(conn, session_key, shutdown_event):
    """
    Thread function to continuously send messages entered by the user.

    Args:
        conn (socket.socket): Active socket connection to peer.
        session_key (bytes): Session key for message encryption.
        shutdown_event (threading.Event): Event to signal threads to stop.
    """

    counter = 0
    try:
        # Check if it is signalled that thread is shut down
        while not shutdown_event.is_set():
            # Here whe wait for user input to send message
            try:
                msg = input(" ")
            except KeyboardInterrupt: # Handle Ctrl_C gracefully
                print("\n[INFO] Send thread interrupted. Closing connection...")
                shutdown_event.set()
                break  # exit the loop cleanly

            # Generate the 12-byte nonce from the counter
            nonce = counter.to_bytes(12, "big") 
            if msg.lower() == "exit":
                try:
                    # Encrypt the exit message and send with the nonce
                    ciphertext = encrypt_message(session_key, msg, nonce)
                    conn.sendall(nonce + ciphertext)
                except:
                    print("Connection is already closed, failed to send ciphertext.")
                    pass
                print("Closing connection…")
                # Signal the connection is being shut down: can be checked by other thread
                shutdown_event.set() 
                break
            else:
                # Encrypt a normal message
                ciphertext = encrypt_message(session_key, msg, nonce)
                try:
                    conn.sendall(nonce + ciphertext)
                except:
                    # If sending fails, signal shutdown and break the loop
                    print("Failed to send ciphertext, breaking the connection.")
                    shutdown_event.set()
                    break
            counter += 1
    finally:
        # Ensure shutdown and close the socket
        shutdown_event.set()
        try: conn.shutdown(socket.SHUT_RDWR) # Stop further sends and receives
        except: pass
        try: conn.close() # Close connection
        except: pass





