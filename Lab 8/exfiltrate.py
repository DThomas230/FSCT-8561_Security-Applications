#!/usr/bin/env python
"""
Part B - Stepic Steganography
Hide port scan data [80, 443, 3478, 5060] inside profile.png using Stepic
"""

from PIL import Image
import stepic

# Load carrier image
carrier = Image.open("profile.png")

# Define footprinting data (port scan results from conferencing tools)
footprint_data = "CONF_TOOL_SCAN: 80, 443, 3478, 5060".encode('utf-8')

# Encode and save
stego_image = stepic.encode(carrier, footprint_data)
stego_image.save("profile_secret.png")

print("=" * 50)
print("Part B - Stepic Steganography")
print("=" * 50)
print(f"Carrier image: profile.png")
print(f"Hidden data: {footprint_data.decode('utf-8')}")
print(f"Output image: profile_secret.png")
print("\nData hidden successfully!")
