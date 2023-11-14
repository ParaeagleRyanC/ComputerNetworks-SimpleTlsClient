import crypto_utils as utils
from message import Message, MessageType
import logging
import argparse
import re
import socket
import sys
import secrets


DEFAULT_RECEIVE_SIZE = 1024
NONCE_BYTES = 32
SERVER_ENCRYPTION_KEY = 0
SERVER_DATA_INTEGRITY_KEY = 1
CLIENT_ENCRYPTION_KEY = 2
CLIENT_DATA_INTEGRITY_KEY = 3


# sends HELLO and receives NONCE & CERTIFICATE Received
def send_hello():
    hello_message = Message(MessageType.HELLO).to_bytes()
    try:
        client.sendall(hello_message)
        logging.info(f"HELLO sent: {hello_message}")
    except Exception as ex:
        logging.error(f"Failed to send HELLO because: {ex}")
        sys.exit(1)

    try:
        response = Message.from_socket(client).data
        logging.info(f"NONCE & CERTIFICATE Received: {response}")
        return (
            response,
            hello_message,
            Message(MessageType.CERTIFICATE, response).to_bytes(),
        )
    except Exception as ex:
        logging.error(f"Failed to receive NOUCE & Certificate because: {ex}")
        sys.exit(1)


# connects to the server with given host and port
def connect(host, port):
    try:
        global client
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        logging.info("Connected to the server.")
        return client
    except Exception as ex:
        logging.error(f"Failed to connect because: {ex}")
        sys.exit(1)


# verify a certificate exists and returns it
def get_certificate(data):
    certificate = utils.load_certificate(data)
    if certificate == None:
        logging.error("No certificate! Exiting...")
        sys.exit(1)
    logging.info("Successfully retreived certificate!")
    return certificate


# generates client nonce
def generate_nonce():
    return secrets.token_bytes(NONCE_BYTES)


# sends encrypted nonce to the server and receives a hash
def send_encrypted_nonce(encrypted_nonce):
    encrypted_nonce_message = Message(MessageType.NONCE, encrypted_nonce).to_bytes()
    try:
        client.sendall(encrypted_nonce_message)
        logging.info(f"ENCRYPTED_NONCE sent: {encrypted_nonce_message}")
    except Exception as ex:
        logging.error(f"Failed to send ENCRYPTED_NONCE because: {ex}")
        sys.exit(1)

    try:
        response = Message.from_socket(client).data
        logging.info(f"HASH Received: {response}")
        return (response, encrypted_nonce_message)
    except Exception as ex:
        logging.error(f"Failed to receive HASH because: {ex}")
        sys.exit(1)


# verifies the hash from the server is valid
def verify_server_hash(server_hash, key, cumulated_data):
    if not utils.mac(cumulated_data, key) == server_hash:
        logging.error("Cannot verify Server Hash. Exiting...")
        sys.exit(1)


# generates a client hash
def generate_hash(data, key):
    return utils.mac(data, key)


# sends client hash to the server
def send_client_hash(client_hash):
    client_hash_message = Message(MessageType.HASH, client_hash).to_bytes()
    try:
        client.sendall(client_hash_message)
        logging.info(f"CLIENT HASH sent: {client_hash_message}")
    except Exception as ex:
        logging.error(f"Failed to send CLIENT HASH because: {ex}")
        sys.exit(1)


# loops to receive encrypted data until server disconnects
def receive_encrypted_data(keys):
    current_sequence = 0
    complete_data = b""
    try:
        while True:
            encrypted_data = Message.from_socket(client)
            logging.info(f"ENCRYPTED DATA Received: {encrypted_data}")
            if not encrypted_data:
                logging.info("Server disconnected.")
                return complete_data

            decrypted_data = utils.decrypt(
                encrypted_data.data, keys[SERVER_ENCRYPTION_KEY]
            )

            sequence_number, data_chunk, mac = desolve_decrypted_data(decrypted_data)
            current_sequence = verify_sequence_number(current_sequence, sequence_number)
            verify_mac(data_chunk, mac, keys[SERVER_DATA_INTEGRITY_KEY])

            complete_data += data_chunk
    except Exception as ex:
        logging.error(f"Failed to receive ENCRYPTED DATA because: {ex}")
        sys.exit(1)


# verifies the sequence number is in order
def verify_sequence_number(current_number, new_number):
    int_new_number = int.from_bytes(new_number, byteorder="big")
    if not current_number == int_new_number:
        logging.error("Sequence number does not match! Exiting...")
        sys.exit(0)
    current_number += 1
    return current_number


# verifies the mac matches the data chunk
def verify_mac(data_chunk, mac, key):
    if not utils.mac(data_chunk, key) == mac:
        logging.error("MAC failed to be verified! Exiting...")
        sys.exit(0)


# breaks down the decrypted data in to sequence number, data chunk, and mac
def desolve_decrypted_data(data):
    return data[:4], data[4 : len(data) - 32], data[-32:]


# outputs to stdout or a file
def output(data, filename):
    if filename == "-":
        print(data)
    else:
        try:
            with open(filename, "wb") as file:
                file.write(data)
        except Exception as ex:
            logging.error(f"Failed to write to file because: {ex}")
            sys.exit(0)


# main function that executes a series of functions
def main(host, port, filename):
    connect(host, port)

    (
        nonce_with_certificate,
        client_hello_message,
        server_certificate_message,
    ) = send_hello()

    certificate = get_certificate(nonce_with_certificate[NONCE_BYTES:])

    server_nonce = nonce_with_certificate[:NONCE_BYTES]

    client_nonce = generate_nonce()

    encrypted_nonce = utils.encrypt_with_public_key(
        client_nonce, certificate.public_key()
    )

    server_hash, client_nonce_message = send_encrypted_nonce(encrypted_nonce)

    keys = utils.generate_keys(client_nonce, server_nonce)

    verify_server_hash(
        server_hash,
        keys[SERVER_DATA_INTEGRITY_KEY],
        client_hello_message + server_certificate_message + client_nonce_message,
    )

    client_hash = generate_hash(
        client_hello_message + server_certificate_message + client_nonce_message,
        keys[CLIENT_DATA_INTEGRITY_KEY],
    )

    send_client_hash(client_hash)
    final_data = receive_encrypted_data(keys)

    output(final_data, filename)


# regex to check user input file is valid
def file_regex(file_name):
    if not re.match(r"^(-|[^.]*\.[pP][nN][gG])$", file_name):
        raise argparse.ArgumentTypeError(
            "It must be a PNG file extension. Use - for stdout."
        )
    return file_name


# function to parse arguments
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "file",
        type=file_regex,
        help="The file name to save to. It must be a PNG file extension. Use - for stdout.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        required=False,
        default=8087,
        help="Port to connect to.",
    )
    parser.add_argument(
        "--host",
        type=str,
        required=False,
        default="localhost",
        help="Hostname to connect to.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Turn on debugging output.",
    )
    return parser.parse_args()


# main function
if __name__ == "__main__":
    args = parse_arguments()
    # if verbose flag is high, turn on verbose
    if args.verbose:
        logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.DEBUG)
    try:
        main(args.host, args.port, args.file)
    except KeyboardInterrupt:
        logging.info("Keyboard Interrupt Detected!")
