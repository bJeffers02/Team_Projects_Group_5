import serial
import cv2

from detect import run_detection
from transmission import (
    sender_handshake,
    send_control_signal,
    send_chunk,
    TYPE_START_IMG,
    TYPE_END_IMG,
)
import crypt

# --- Configuration ---
SERIAL_PORT = '/tmp/ttyV1'  # Target port ('/dev/ttyUSBx' or 'COMx')
BAUD_RATE = 9600

IMAGES_PATH = 'raw_images/'
CROPPED_PATH = "processed_images/"


def preprocess_images(image_list: list, chunk_size: int = 64) -> list[dict]:
    preprocessed_data = []

    for img_id, cv2_img in enumerate(image_list):
        # 1. Serialize OpenCV image matrix to PNG byte stream (Lossless)
        success, encoded_img = cv2.imencode(".png", cv2_img)
        if not success:
            raise ValueError(
                f"[Preprocess] Failed to encode image index {img_id} to PNG."
            )

        raw_bytes = encoded_img.tobytes()

        # 2. Slice raw bytes into fixed-size chunks
        chunks = [
            raw_bytes[i : i + chunk_size]
            for i in range(0, len(raw_bytes), chunk_size)
        ]

        # 3. Calculate unencrypted MD5 checksum for each chunk
        md5s = [crypt.md5sum(chunk) for chunk in chunks]

        preprocessed_data.append(
            {"chunks": chunks, "md5s": md5s}
        )
    return preprocessed_data


def main():

    _, public_key = crypt.generate_keys()
    
    images = run_detection(IMAGES_PATH, CROPPED_PATH)
    processed_images = preprocess_images(images)


    serial_connection = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    print(f"Listening on {SERIAL_PORT} at {BAUD_RATE} baud...")

    rx_key = sender_handshake(serial_connection, public_key)

    for img_id, img_data in enumerate(processed_images):
        chunks = img_data["chunks"]
        md5s = img_data["md5s"]
        total_chunks = len(chunks)

        print(f"\n[TX] Sending Image {img_id + 1}/{len(processed_images)} ({total_chunks} chunks)...")

        # Signal START of image stream
        send_control_signal(serial_connection, TYPE_START_IMG)

        # Iterate and send each chunk
        for chunk_idx, (raw_chunk, md5_str) in enumerate(zip(chunks, md5s)):
            # Encrypt raw chunk with receiver's public key
            encrypted_payload = crypt.encrypt(raw_chunk, rx_key)

            # Convert MD5 string to bytes
            md5_bytes = md5_str.encode('ascii')

            # Transmit chunk
            success = send_chunk(serial_connection, encrypted_payload, md5_bytes)

            if not success:
                print(f"[TX Error] Failed to send chunk {chunk_idx + 1}/{total_chunks}. Aborting image.")
                send_control_signal(serial_connection, TYPE_END_IMG)
                break

            print(f"[TX] Sent chunk {chunk_idx + 1}/{total_chunks}", end='\r')

        # Signal END of image stream
        send_control_signal(serial_connection, TYPE_END_IMG)
        print(f"\n[TX] Finished Image {img_id + 1}")

    print("\n[TX] All images successfully transmitted!")

if __name__ == '__main__':
    main()