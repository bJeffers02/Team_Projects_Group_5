import base64
import cv2
import numpy as np
import serial
import time

# --- Configuration ---
SERIAL_PORT = '/dev/ttyUSB0'  # Target port ('/dev/ttyUSBx' or 'COMx')
BAUD_RATE = 9600
IMAGE_PATH = 'images/image9.png'
PADDING = 5                   # Extra border around detected target (pixels)
CHUNK_SIZE = 64              # Serial transmission chunk size


def load_image(filepath):
    """Load image from disk."""
    img = cv2.imread(filepath)
    if img is None:
        raise FileNotFoundError(f"Could not load image at {filepath}")
    return img


def find_red_circle_crop(img, padding=20):
    """Detect red pixels in HSV space, locate bounding box, and return cropped square image."""
    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

    # Combine upper and lower red ranges in HSV space
    mask1 = cv2.inRange(hsv, np.array([0, 100, 100]), np.array([10, 255, 255]))
    mask2 = cv2.inRange(hsv, np.array([160, 100, 100]), np.array([180, 255, 255]))
    mask = mask1 | mask2

    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        raise ValueError("No red circle detected in the image.")

    # Get largest red contour coordinates
    largest_contour = max(contours, key=cv2.contourArea)
    x, y, w, h = cv2.boundingRect(largest_contour)

    # Calculate square crop boundaries with padding
    center_x, center_y = x + w // 2, y + h // 2
    half_side = max(w, h) // 2 + padding

    img_h, img_w = img.shape[:2]
    y1 = max(0, center_y - half_side)
    y2 = min(img_h, center_y + half_side)
    x1 = max(0, center_x - half_side)
    x2 = min(img_w, center_x + half_side)

    return img[y1:y2, x1:x2]


def encode_to_jpg(img, quality=80):
    """Compress image array into JPEG binary bytes."""
    success, encoded_img = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    if not success:
        raise RuntimeError("Failed to encode cropped image to JPEG format.")
    return encoded_img


def transmit_base64_image(img, port, baud_rate):
    b64_string = base64.b64encode(img.tobytes()).decode('ascii')
    payload = f"<START_IMG>{b64_string}<END_IMG>\n".encode('ascii')

    ser = serial.Serial(port, baud_rate, timeout=1)
    try:
        print(f"Transmitting Base64 payload ({len(payload)} bytes)...")
        total_chunks = (len(payload) + CHUNK_SIZE - 1) // CHUNK_SIZE

        for i in range(total_chunks):
            chunk = payload[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
            ser.write(chunk)
            ser.flush()
            print(f"Sent chunk {i + 1}/{total_chunks}", end='\r')
            time.sleep(0.3)  # Pacing to protect Ebyte hardware FIFO

        print("\nTransmission finished.")
    finally:
        ser.close()

def main():
    try:
        # 1. Load source image
        original_img = load_image(IMAGE_PATH)

        # 2. Extract ROI around red circle
        cropped_img = find_red_circle_crop(original_img, padding=PADDING)
        cv2.imwrite('cropped_target.jpg', cropped_img)
        print(f"Target cropped: {cropped_img.shape[1]}x{cropped_img.shape[0]} px.")

        # 3. Compress crop into JPEG bytes
        jpg_payload = encode_to_jpg(cropped_img)

        # 4. Transmit image payload over serial/LoRa
        transmit_base64_image(jpg_payload, SERIAL_PORT, BAUD_RATE)

    except (FileNotFoundError, ValueError, RuntimeError, serial.SerialException) as err:
        print(f"Error: {err}")


if __name__ == '__main__':
    main()