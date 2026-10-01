import struct
import time


MAGIC_HEADER = 0xDEADBEEF

TYPE_HELLO = 0x01
TYPE_HELLO_ACK = 0x02
TYPE_KEY_EXCHANGE = 0x03

TYPE_START_IMG = 0x04
TYPE_END_IMG = 0x05
TYPE_DATA_CHUNK = 0x06
TYPE_ACK = 0x07
TYPE_NACK = 0x08

HEADER_FORMAT = "!IBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

KEY_CHUNK_HEADER_FORMAT = "!HH"
KEY_CHUNK_HEADER_SIZE = struct.calcsize(KEY_CHUNK_HEADER_FORMAT)

MAX_PAYLOAD_SIZE = 64
KEY_CHUNK_DATA_SIZE = MAX_PAYLOAD_SIZE - KEY_CHUNK_HEADER_SIZE

TIMEOUT = 2.0
MAX_RETRIES = 5


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
    # Keep buffer between calls so fragmented frames aren't lost.
    if not hasattr(serial_conn, "_rx_buffer"):
        serial_conn._rx_buffer = bytearray()

    buffer = serial_conn._rx_buffer
    start_time = time.time()
    magic_bytes = struct.pack("!I", MAGIC_HEADER)

    while time.time() - start_time < timeout:
        if serial_conn.in_waiting > 0:
            buffer.extend(serial_conn.read(serial_conn.in_waiting))

        magic_idx = buffer.find(magic_bytes)

        if magic_idx == -1:
            if len(buffer) > len(magic_bytes) - 1:
                del buffer[:-(len(magic_bytes) - 1)]
            time.sleep(0.005)
            continue

        if magic_idx > 0:
            del buffer[:magic_idx]

        if len(buffer) < HEADER_SIZE:
            time.sleep(0.005)
            continue

        magic, msg_type, payload_len = struct.unpack(HEADER_FORMAT, buffer[:HEADER_SIZE])

        if magic != MAGIC_HEADER or payload_len > MAX_PAYLOAD_SIZE:
            del buffer[0]
            continue

        total_frame_size = HEADER_SIZE + payload_len

        if len(buffer) < total_frame_size:
            time.sleep(0.005)
            continue

        packet = bytes(buffer[:total_frame_size])
        del buffer[:total_frame_size]

        return msg_type, packet[HEADER_SIZE:]

    return None, None
    

def send_public_key(serial_conn, public_key: bytes):
    total_chunks = (len(public_key) + KEY_CHUNK_DATA_SIZE - 1) // KEY_CHUNK_DATA_SIZE

    for chunk_index in range(total_chunks):
        start = chunk_index * KEY_CHUNK_DATA_SIZE
        chunk_data = public_key[start:start + KEY_CHUNK_DATA_SIZE]

        chunk_header = struct.pack(KEY_CHUNK_HEADER_FORMAT, chunk_index, total_chunks)
        payload = chunk_header + chunk_data

        retries = 0

        while retries < MAX_RETRIES:
            serial_conn.write(pack_message(TYPE_KEY_EXCHANGE, payload))
            serial_conn.flush()

            print(f"[TX] Sent Public Key chunk {chunk_index + 1}/{total_chunks} ({len(chunk_data)} bytes)")

            msg_type, ack_payload = read_message(serial_conn, timeout=TIMEOUT)

            if msg_type == TYPE_ACK:
                print(f"[TX] Key chunk {chunk_index + 1}/{total_chunks} ACK received")
                break

            retries += 1
            print(f"[TX] No ACK for key chunk {chunk_index + 1}; retrying ({retries}/{MAX_RETRIES})")
            time.sleep(0.3)

        if retries >= MAX_RETRIES:
            raise RuntimeError(f"Failed to send key chunk {chunk_index + 1}")



def receive_public_key(serial_conn, timeout: float = 15.0):
    key_chunks = {}
    total_chunks = None
    start_time = time.time()

    while time.time() - start_time < timeout:
        msg_type, payload = read_message(serial_conn, timeout=1.0)

        if msg_type != TYPE_KEY_EXCHANGE or not payload:
            continue

        if len(payload) < KEY_CHUNK_HEADER_SIZE:
            continue

        chunk_index, received_total = struct.unpack(KEY_CHUNK_HEADER_FORMAT, payload[:KEY_CHUNK_HEADER_SIZE])
        chunk_data = payload[KEY_CHUNK_HEADER_SIZE:]

        if total_chunks is None:
            total_chunks = received_total

        key_chunks[chunk_index] = chunk_data

        print(f"[RX] Received Public Key chunk {chunk_index + 1}/{received_total} ({len(chunk_data)} bytes)")

        ack = struct.pack("!H", chunk_index)
        serial_conn.write(pack_message(TYPE_ACK, ack))
        serial_conn.flush()

        print(f"[RX] Sent ACK for chunk {chunk_index + 1}/{received_total}")

        if len(key_chunks) == total_chunks and all(i in key_chunks for i in range(total_chunks)):
            public_key = b"".join(key_chunks[i] for i in range(total_chunks))
            print(f"[RX] Reassembled Public Key: {len(public_key)} bytes")
            return public_key

    return None


def sender_handshake(serial_conn, tx_public_key: bytes, retry_delay: float = 1.0) -> bytes:
    print("[TX] Initiating Handshake...")

    while True:
        serial_conn.write(pack_message(TYPE_HELLO))
        serial_conn.flush()
        print("[TX] Sent HELLO... waiting for ACK")

        msg_type, _ = read_message(serial_conn, timeout=retry_delay)

        if msg_type == TYPE_HELLO_ACK:
            print("[TX] Received HELLO_ACK from Receiver!")
            break

    print(f"[TX] Sending Public Key ({len(tx_public_key)} bytes)...")
    send_public_key(serial_conn, tx_public_key)

    print("[TX] Waiting for Receiver Key...")
    rx_public_key = receive_public_key(serial_conn, timeout=15.0)

    if rx_public_key is None:
        raise RuntimeError("[TX] Failed to receive Receiver Public Key")

    print(f"[TX] Received Receiver Public Key ({len(rx_public_key)} bytes)")
    print("[TX] Handshake & Key Exchange Complete!\n")

    return rx_public_key


def receiver_handshake(serial_conn, rx_public_key: bytes) -> bytes:
    print("[RX] Listening for sender Handshake...")

    # Wait for HELLO.
    while True:
        msg_type, _ = read_message(serial_conn, timeout=2.0)

        if msg_type == TYPE_HELLO:
            print("[RX] Received HELLO! Sending HELLO_ACK...")
            serial_conn.write(pack_message(TYPE_HELLO_ACK))
            serial_conn.flush()
            print("[RX] Sent HELLO_ACK.")
            break

    # Receive sender key.
    print("[RX] Waiting for Sender's Public Key...")
    tx_public_key = receive_public_key(serial_conn, timeout=15.0)

    if tx_public_key is None:
        raise RuntimeError("[RX] Failed to receive Sender Public Key")

    print(f"[RX] Received Sender Public Key ({len(tx_public_key)} bytes)")

    # Send receiver key.
    print(f"[RX] Sending Receiver Public Key ({len(rx_public_key)} bytes)...")
    send_public_key(serial_conn, rx_public_key)

    print("[RX] Handshake & Key Exchange Complete!\n")

    return tx_public_key
    