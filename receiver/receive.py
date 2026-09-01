import base64
import cv2
import numpy as np
import serial
import time
import re

# --- Configuration ---
SERIAL_PORT = '/dev/ttyUSB0'  # Target port ('/dev/ttyUSBx' or 'COMx')
BAUD_RATE = 9600
OUTPUT_FILE = 'received_crop.jpg'


def open_serial_connection(port, baud_rate):
    """Initialize and return the serial port instance."""
    ser = serial.Serial(port, baud_rate, timeout=1)
    print(f"Listening on {port} at {baud_rate} baud...")
    return ser


def capture_raw_stream(ser, start_marker="<START_IMG>", end_marker="<END_IMG>"):
    """Listen on serial port and extract the raw payload trapped between markers."""
    raw_buffer = ""
    recording = False

    while True:
        if ser.in_waiting > 0:
            incoming = ser.read(ser.in_waiting).decode('ascii', errors='ignore')
            raw_buffer += incoming

            # 1. Look for start marker
            if not recording and start_marker in raw_buffer:
                print("Start marker detected! Capturing frame...")
                recording = True
                raw_buffer = raw_buffer.split(start_marker, 1)[1]

            # 2. Look for end marker
            if recording:
                if end_marker in raw_buffer:
                    print("End marker detected! Payload complete.")
                    return raw_buffer.split(end_marker, 1)[0]
                else:
                    print(f"Receiving string... ({len(raw_buffer)} chars)", end='\r')

        time.sleep(0.02)


def sanitize_base64_string(raw_string):
    """Strip out noise, modem responses (like #RECV:), and non-Base64 characters."""

    cleaned = re.sub(r'#RECV:\s', '', raw_string)
    cleaned = re.sub(r'[\r\n\t\s]', '', cleaned)

    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    sanitized = "".join(c for c in cleaned if c in valid_chars)

    missing_padding = len(sanitized) % 4
    if missing_padding:
        sanitized += "=" * (4 - missing_padding)
        
    if not sanitized:
        raise ValueError("Sanitized Base64 payload is empty.")
    return sanitized


def decode_base64_to_image(b64_string):
    """Decode Base64 ASCII string into OpenCV BGR image matrix with fallback decoding."""
    try:
        # Validate and decode Base64
        jpg_bytes = base64.b64decode(b64_string, validate=False)
    except Exception as e:
        raise ValueError(f"Base64 decoding failed: {e}")

    np_arr = np.frombuffer(jpg_bytes, dtype=np.uint8)
    
    # Use IMREAD_COLOR to decode the JPEG array
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    if img is None:
        raise ValueError("OpenCV failed to decode raw JPEG bytes due to in-stream corruption.")
    
    return img

def save_and_display_image(img, output_path):
    """Save reconstructed image to disk and render in a preview window."""
    cv2.imwrite(output_path, img)
    print(f"Image successfully saved to: {output_path}")

    cv2.imshow("Reassembled Target", img)
    print("Press any key on the image window to exit.")
    cv2.waitKey(0)
    cv2.destroyAllWindows()


def main():
    ser = None
    try:
        # 1. Connect
        ser = open_serial_connection(SERIAL_PORT, BAUD_RATE)

        # 2. Extract payload string
        raw_payload = capture_raw_stream(ser)

        # 3. Clean noise/AT responses
        clean_b64 = sanitize_base64_string(raw_payload)

        # 4. Decode to OpenCV image
        image = decode_base64_to_image(clean_b64)

        # 5. Output result
        save_and_display_image(image, OUTPUT_FILE)

    except (serial.SerialException, ValueError, KeyboardInterrupt) as err:
        print(f"\nError: {err}")
    finally:
        if ser and ser.is_open:
            ser.close()
            print("Serial connection closed.")


if __name__ == '__main__':
    main()