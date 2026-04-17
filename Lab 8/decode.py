#!/usr/bin/env python
"""
Part C - Verification & Analysis
Decode script to recover hidden port list from profile_secret.png
"""

from PIL import Image
import stepic
import os

print("=" * 50)
print("Part C - Verification & Analysis")
print("=" * 50)

# ============================================
# 1. Extract hidden data from stego image
# ============================================
print("\n1. EXTRACTION")
print("-" * 40)

stego_image = Image.open("profile_secret.png")
decoded_data = stepic.decode(stego_image)

print(f"Decoded data: {decoded_data}")

# Parse the port list
if "CONF_TOOL_SCAN:" in decoded_data:
    ports_str = decoded_data.split(":")[1].strip()
    ports = [int(p.strip()) for p in ports_str.split(",")]
    print(f"Extracted port list: {ports}")

# ============================================
# 2. File Size Comparison
# ============================================
print("\n2. FILE SIZE CHECK")
print("-" * 40)

original_size = os.path.getsize("profile.png")
stego_size = os.path.getsize("profile_secret.png")
size_diff = stego_size - original_size
percent_change = (size_diff / original_size) * 100

print(f"Original (profile.png): {original_size:,} bytes")
print(f"Stego (profile_secret.png): {stego_size:,} bytes")
print(f"Difference: {size_diff:+,} bytes ({percent_change:+.2f}%)")

if abs(percent_change) < 5:
    print("\n→ The file size change is minimal, making the steganography")
    print("  difficult to detect through simple file size analysis.")