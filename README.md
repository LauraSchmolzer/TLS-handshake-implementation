# TLS handshake implementation in Python
This project is meant to simulate a simplified TLS handshake in Python to learn the core cryptographic operations, message flows and security guarantees that are involved in establishing a secure communication channel between Client and Server.

This project will focus on my personal learning objectives on applied cryptography and is not intended to be a production-ready TLS implementation. My project will not include any TLS extensions.

## Objectives:
- Develop a Python-based TLS client and server that communicate over separate terminal.
- Implement a minimal, but cryptographically correct, TLS handshake.
- Provide detailed logging for educational and debugging purposes.
- Enable an interactive terminal that supports secure bidirectional messaging between client and server after the session establishment.
- Shortly emphasise and report the cryptographic inner workings of TLS 1.3.

## How to Run the Server and Client

1. Open **two separate terminal windows** (or tabs).

2. In the first terminal, start the server:

   ```bash
   python server.py
   ```
3. In the second terminal, start the client:
   ```bash
   python client.py
   ```
4. The client will connect to the server, perform the handshake, and then you can start sending messages interactively.

Notes: 
- Make sure the Server is running before the Client as it is Client-initiated. 
- The connection uses HOST = "127.0.0.1" and PORT = 4444. Ensure no other process is using that port.
- Both scripts should be in the same directory, else adjust the paths. 
