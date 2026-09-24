"""Find red annotation circles in Death Star plan images and crop what's inside them.

How it works, in one breath: the plans are basically grayscale space scenes, so a
red ring is the only saturated thing in the frame. We make a mask of "what's red",
find the ring shapes in that mask, and cut out the hole in the middle of each one.

Usage:
    python detect.py IN_DIR OUT_DIR [--debug]
"""

from pathlib import Path
import cv2
import numpy as np

# --- tuning ---------------------------------------------------------------
# These are the knobs. Everything here was measured off the three sample plans.

# What counts as "red" in HSV. Red sits at both ends of the hue wheel (near 0 and
# near 180), so it takes two ranges instead of one. The three numbers are
# hue / saturation / brightness.
#
# The 150 saturation floor is the important one. Anything lower and the mask
# starts grabbing the blue nebula background, which makes the ring come out
# ragged and fail the roundness check below.
RED_LO_A = (0, 150, 60)
RED_HI_A = (12, 255, 255)
RED_LO_B = (168, 150, 60)
RED_HI_B = (180, 255, 255)

KERNEL = 5          # patches tiny gaps in the ring caused by smoothed edges
MIN_AREA = 150      # real rings measure ~1600 px; background junk topped out at 23
MIN_ROUND = 0.85    # 1.0 is a perfect circle; our samples score 0.88-0.91
PADDING = 5


def load_img(path):
    """Read as plain 3-channel colour.
    """
    img = cv2.imread(str(path), cv2.IMREAD_COLOR)
    if img is None:
        raise OSError(f"cannot read {path}")
    return img


def red_mask(img):
    """
    Black-and-white image where white means 'this pixel is red'.
    """
    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    mask = cv2.bitwise_or(
        cv2.inRange(hsv, RED_LO_A, RED_HI_A),
        cv2.inRange(hsv, RED_LO_B, RED_HI_B),
    )
    # Edges of the ring are smoothed, so the mask comes out with pinholes.
    # "Close" fills them in so the ring is one solid loop.
    return cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((KERNEL, KERNEL), np.uint8))


def roundness(c):
    """How circle-like a shape is, from 0 to 1.
    """
    p = cv2.arcLength(c, True)
    return 4 * np.pi * cv2.contourArea(c) / (p * p) if p else 0.0


def find_best_contour(mask):
    cnts, _ = cv2.findContours(
       mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_NONE
    )
    if not cnts:
        return None

    best_contour = None
    best_score = MIN_ROUND
    for c in cnts:
        area = cv2.contourArea(c)
        if area < MIN_AREA:
            continue

        round_score = roundness(c)

        if round_score > best_score:
            best_score = round_score
            best_contour = c

    return best_contour

def crop(img, c):
    """Crop the contour out of the original image with padding."""
    
    x, y, w, h = cv2.boundingRect(c)
    img_h, img_w = img.shape[:2]

    x1 = max(0, x - PADDING)
    y1 = max(0, y - PADDING)
    x2 = min(img_w, x + w + PADDING)
    y2 = min(img_h, y + h + PADDING)

    cropped = img[y1:y2, x1:x2]
    if cropped.size == 0:
        return None

    return cropped

def detect(path):
    img = load_img(path)
    mask = red_mask(img)
    contour = find_best_contour(mask)
    if contour is not None: 
        cropped = crop(img, contour)
        return cropped
    return None


def run_detection(in_dir, out_dir):
    """Process a folder of plans."""
    in_dir, out_dir = Path(in_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    images = []
    for path in sorted(in_dir.glob("*.png")):
        cropped = detect(path)
        if cropped is not None:
            print(f"Detected Death Star vulnerability in {path}. Saving to {out_dir}")

            images.append(cropped)

            name = f"{path.stem}_processed.png"
            cv2.imwrite(str(out_dir / name), cropped)

    if len(images) < 10:
        print(f"Warning: Only {len(images)} images were detected with Death Star vulnerabilities.")

    return images


