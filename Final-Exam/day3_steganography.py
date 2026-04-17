# day3_steganography.py — Steganographic Extraction (Day 3 / Lab 8)
# Recovers the Architect's Manifesto from evidence.png using LSB steganography.

from PIL import Image
import stepic
from config import IMAGE_PATH, MANIFEST_FILE


def extract_message(image_path: str) -> str:
    """Open image and decode the LSB-hidden message using stepic."""
    print(f"[*] Opening image: {image_path}")
    img = Image.open(image_path)

    raw = stepic.decode(img)

    # stepic may return bytes or str depending on version
    message = raw.decode('utf-8') if isinstance(raw, bytes) else raw
    return message


def save_manifest(message: str, output_path: str) -> None:
    """Write the recovered message to a text file."""
    with open(output_path, 'w') as f:
        f.write(message)
    print(f"[+] Manifest saved to: {output_path}")


if __name__ == '__main__':
    message = extract_message(IMAGE_PATH)

    print("\n--- Extracted Message ---")
    print(message)
    print("-------------------------\n")

    # Quick sanity check: exam states message begins with "The vault is..."
    if message.startswith("The vault is"):
        print("[+] Signature check PASSED — message starts with 'The vault is'")
    else:
        print("[!] Signature check WARNING — unexpected message start.")

    save_manifest(message, MANIFEST_FILE)
