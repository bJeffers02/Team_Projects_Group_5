import os
import cv2
import numpy as np
import serial

from transmission import receiver_handshake, read_message, pack_message
from transmission import (
    TYPE_START_IMG,
    TYPE_DATA_CHUNK,
    TYPE_END_IMG,
    TYPE_ACK,
    TYPE_NACK,
)
import crypt

# --- Configuration ---
SERIAL_PORT = '/tmp/ttyV0' 
BAUD_RATE = 9600
OUTPUT_DIR = 'received_images/'
MD5_LEN = 32


def main():

    private_key, public_key = crypt.generate_keys()

    serial_connection = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    print(f"Listening on {SERIAL_PORT} at {BAUD_RATE} baud...")

    tx_key = receiver_handshake(serial_connection, public_key)

    current_image_bytes = bytearray()
    image_counter = 0
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    while True:
        try:
            msg_type, payload = read_message(serial_connection, timeout=1.0)

            # Skip empty timeout reads
            if msg_type is None:
                continue


            elif msg_type == TYPE_START_IMG:
                image_counter += 1
                current_image_bytes = bytearray()
                print(f"\n[RX] Received TYPE_START_IMG -> Starting Image #{image_counter}")
                serial_connection.write(pack_message(TYPE_ACK))
                serial_connection.flush()


            elif msg_type == TYPE_DATA_CHUNK:
                if not payload or len(payload) <= MD5_LEN:
                    print("[RX Error] Corrupted DATA_CHUNK payload length.")
                    serial_connection.write(pack_message(TYPE_NACK))
                    serial_connection.flush()
                    continue

                # Unpack MD5 and Encrypted Payload
                expected_md5 = payload[:MD5_LEN].decode('ascii')
                encrypted_chunk = payload[MD5_LEN:]

                try:
                    # Decrypt with Receiver's Private Key
                    raw_chunk = crypt.decrypt(encrypted_chunk, private_key)

                    # Compute MD5 on decrypted payload and verify
                    calculated_md5 = crypt.md5sum(raw_chunk)
                    if calculated_md5 == expected_md5:
                        current_image_bytes.extend(raw_chunk)
                        serial_connection.write(pack_message(TYPE_ACK))
                        serial_connection.flush()
                        print(f"[RX] Chunk received & verified ({len(raw_chunk)} bytes)", end='\r')
                    else:
                        print(f"\n[RX Error] MD5 Mismatch! Expected {expected_md5}, got {calculated_md5}")
                        serial_connection.write(pack_message(TYPE_NACK))
                        serial_connection.flush()

                except Exception as e:
                    print(f"\n[RX Error] Decryption failed: {e}")
                    serial_connection.write(pack_message(TYPE_NACK))
                    serial_connection.flush()


            elif msg_type == TYPE_END_IMG:
                print(f"\n[RX] Received TYPE_END_IMG for Image #{image_counter}")
                serial_connection.write(pack_message(TYPE_ACK))
                serial_connection.flush()

                if current_image_bytes:
                    img_np = np.frombuffer(current_image_bytes, dtype=np.uint8)
                    cv2_img = cv2.imdecode(img_np, cv2.IMREAD_COLOR)

                    if cv2_img is not None:
                        out_path = os.path.join(OUTPUT_DIR, f"received_{image_counter}.jpg")
                        cv2.imwrite(out_path, cv2_img)
                        print(f"[RX Success] Image #{image_counter} saved to {out_path}")
                    else:
                        print(f"[RX Error] Failed to decode JPEG buffer for Image #{image_counter}")

        except KeyboardInterrupt:
            print("\n[RX] Stopping receiver...")
            break
        except Exception as e:
            print(f"[RX Exception] Unexpected error: {e}")

if __name__ == '__main__':
    main()