# Simple TLS Client

This program is a simplified version of TLS. TLS is a general purpose security transfer protocol that often works with HTTP.

The client and the server interact in the following manner:
1. Client sends a `Hello` to the server and receives a `Certificate`.
2. Client generates, and sends an encrypted `Nonce` tothe server and receives a `Hash`.
3. Client verifies the `Hash` and sends its own `Hash`.
4. Server verifies the `Hash` from the client and begins sending encrypted information to the client.

This program demonstrates the knowledge of security principles and building a client for a encrypted and integrity protected communication protocol.
