import struct
import time

# Magic header to filter out radio noise (4 bytes)
MAGIC_HEADER = 0xDEADBEEF

# Control Message Types
TYPE_HELLO = 0x01
TYPE_HELLO_ACK = 0x02
TYPE_KEY_EXCHANGE = 0x03

# Streaming Message Types
TYPE_START_IMG = 0x04
TYPE_END_IMG = 0x05
TYPE_DATA_CHUNK = 0x06
TYPE_ACK = 0x07
TYPE_NACK = 0x08

# Header format: Magic(4B) + MsgType(1B) + PayloadLength(2B) = 7 Bytes total
HEADER_FORMAT = "!IBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Key exchange chunking
KEY_CHUNK_HEADER_FORMAT = "!HH"  # chunk_index, total_chunks
KEY_CHUNK_HEADER_SIZE = struct.calcsize(KEY_CHUNK_HEADER_FORMAT)

# Leave room for the chunk header inside MAX_PAYLOAD_SIZE
MAX_PAYLOAD_SIZE = 64
TIMEOUT = 2.0  # seconds to wait for ACK
MAX_RETRIES = 5

KEY_CHUNK_DATA_SIZE = MAX_PAYLOAD_SIZE - KEY_CHUNK_HEADER_SIZE

def pack_message(msg_type: int, payload: bytes = b"") -> bytes:
    """Builds a binary frame with a magic header, message type, length, and payload."""
    header = struct.pack(HEADER_FORMAT, MAGIC_HEADER, msg_type, len(payload))
    return header + payload


def send_control_signal(serial_conn, signal_type: int):
    """Helper to transmit a control signal (e.g., START/END_IMG) and wait for ACK."""
    ack_received = False
    while not ack_received:
        serial_conn.write(pack_message(signal_type))
        serial_conn.flush()
        msg_type, _ = read_message(serial_conn, timeout=1.0)
        if msg_type == TYPE_ACK:
            ack_received = True


def send_chunk(serial_conn, encrypted_payload: bytes, md5_hash: bytes) -> bool:

    # 1. Package the chunk payload (32-byte MD5 hash + ciphertext payload)
    chunk_payload = md5_hash + encrypted_payload
    packet = pack_message(TYPE_DATA_CHUNK, chunk_payload)

    retries = 0
    while retries < MAX_RETRIES:
        # 2. Transmit the packet over serial
        serial_conn.write(packet)
        serial_conn.flush()

        # 3. Listen for response with timeout
        msg_type, _ = read_message(serial_conn, timeout=TIMEOUT)

        if msg_type == TYPE_ACK:
            return True
        elif msg_type == TYPE_NACK:
            print(f"[TX Warning] NACK received for chunk (attempt {retries + 1}/{MAX_RETRIES}). Retrying...")
        else:
            print(f"[TX Warning] Timeout waiting for ACK (attempt {retries + 1}/{MAX_RETRIES}). Retrying...")

        retries += 1
        time.sleep(0.3)  # Brief delay before retransmitting

    print(f"[TX Error] Failed to send chunk after {MAX_RETRIES} attempts.")
    return False


def read_message(serial_conn, timeout: float = 1.0):
    """Reads a valid protocol frame from serial, handling noise, fragmentation, and byte alignment."""
    start_time = time.time()
    buffer = bytearray()

    while (time.time() - start_time) < timeout:
        if serial_conn.in_waiting > 0:
            buffer.extend(serial_conn.read(serial_conn.in_waiting))

        magic_bytes = struct.pack("!I", MAGIC_HEADER)
        magic_idx = buffer.find(magic_bytes)

        if magic_idx == -1:
            # Magic bytes not found; keep only the last byte in case a 2-byte magic sequence was split
            if len(buffer) > len(magic_bytes) - 1:
                del buffer[: -(len(magic_bytes) - 1)]
            time.sleep(0.005)
            continue

        # Drop garbage noise preceding the magic sequence
        if magic_idx > 0:
            del buffer[:magic_idx]

        # Ensure we have a full header
        if len(buffer) < HEADER_SIZE:
            time.sleep(0.005)
            continue

        # Parse header safely
        magic, msg_type, payload_len = struct.unpack(HEADER_FORMAT, buffer[:HEADER_SIZE])

        # Sanity check payload length to prevent infinite waiting on corrupted length fields
        if payload_len > MAX_PAYLOAD_SIZE:
            # Invalid frame length caused by noise; discard magic byte and keep scanning
            buffer.pop(0)
            continue

        # Wait for full frame (Header + Payload)
        total_frame_size = HEADER_SIZE + payload_len
        if len(buffer) < total_frame_size:
            time.sleep(0.005)
            continue

        # Complete packet extracted
        full_packet = bytes(buffer[:total_frame_size])
        payload = full_packet[HEADER_SIZE:]

        # Remove frame from buffer
        del buffer[:total_frame_size]

        return msg_type, payload

    return None, None
    

def sender_handshake(serial_conn, tx_public_key: bytes, retry_delay: float = 1.0) -> bytes:
    """Executes handshake on the Sender.

    Returns the receiver's Public Key on success.
    """
    print("[TX] Initiating Handshake...")

    # Step 1: Send HELLO until HELLO_ACK is received
    connected = False
    while not connected:
        hello_pkt = pack_message(TYPE_HELLO)
        serial_conn.write(hello_pkt)
        serial_conn.flush()
        print("[TX] Sent HELLO... waiting for ACK")

        msg_type, _ = read_message(serial_conn, timeout=retry_delay)
        if msg_type == TYPE_HELLO_ACK:
            print("[TX] Received HELLO_ACK from Receiver!")
            connected = True

    # Step 2: Key Exchange
    rx_public_key = None
    while rx_public_key is None:
        key_pkt = pack_message(TYPE_KEY_EXCHANGE, tx_public_key)
        serial_conn.write(key_pkt)
        serial_conn.flush()
        print("[TX] Sent Public Key... waiting for Receiver Key")

        msg_type, payload = read_message(serial_conn, timeout=2.0)
        if msg_type == TYPE_KEY_EXCHANGE and payload:
            rx_public_key = payload
            print("[TX] Received Receiver's Public Key!")

    print("[TX] Handshake & Key Exchange Complete!\n")
    return rx_public_key


def receiver_handshake(serial_conn, rx_public_key: bytes) -> bytes:
    """Executes handshake on the Receiver.

    Returns the sender's Public Key on success.
    """
    print("[RX] Listening for sender Handshake...")

    tx_public_key = None
    while tx_public_key is None:
        msg_type, payload = read_message(serial_conn, timeout=2.0)

        # Handle HELLO (or duplicate HELLO if transmitter missed our ACK)
        if msg_type == TYPE_HELLO:
            print("[RX] Received HELLO! Sending HELLO_ACK...")
            serial_conn.write(pack_message(TYPE_HELLO_ACK))
            serial_conn.flush()

        # Handle KEY_EXCHANGE
        elif msg_type == TYPE_KEY_EXCHANGE and payload:
            tx_public_key = payload
            print("[RX] Received Sender's Public Key!")

            # Send back Receiver's Public Key
            reply_key_pkt = pack_message(TYPE_KEY_EXCHANGE, rx_public_key)
            serial_conn.write(reply_key_pkt)
            serial_conn.flush()
            print("[RX] Sent Public Key to Sender.")

    print("[RX] Handshake & Key Exchange Complete!\n")
    return tx_public_key
