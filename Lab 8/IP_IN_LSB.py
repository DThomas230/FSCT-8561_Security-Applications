#!/usr/bin/env python
"""
Part A - Manual LSB Manipulation
Hide 'TARGET:192.168.1.50' inside company_logo.png using manual LSB manipulation
"""

from PIL import Image

def set_LSB(value, bit):
    """Set the least significant bit of a value"""
    if bit == '0':
        value = value & 254  # Clear LSB
    else:
        value = value | 1    # Set LSB
    return value

def get_LSB(value):
    """Get the least significant bit of a value"""
    if value & 1 == 0:
        return '0'
    else:
        return '1'

def hide_message_in_pixels(image_path, message, output_path):
    """
    Hide a message in the first N pixels of an image using LSB manipulation.
    Each character uses 2 pixels (8 bits total: 4 RGBA channels × 2 pixels)
    """
    # Add null terminator
    message += chr(0)
    
    # Open image and convert to RGBA mode
    img = Image.open(image_path)
    img = img.convert('RGBA')
    
    # Get pixel data
    pixels = list(img.getdata())
    width, height = img.size
    
    print(f"Image size: {width}x{height}")
    print(f"Total pixels: {len(pixels)}")
    print(f"Message to hide: '{message[:-1]}'")  # Don't print null terminator
    print(f"Message length: {len(message)-1} characters")
    print(f"Pixels needed: {len(message) * 2} (first {len(message) * 2} pixels)")
    
    # Create new pixel array
    new_pixels = []
    
    # Hide message in first N pixels (2 pixels per character)
    for i in range(len(message)):
        char_int = ord(message[i])
        char_binary = str(bin(char_int))[2:].zfill(8)  # 8-bit binary representation
        
        pix1 = pixels[i * 2]
        pix2 = pixels[(i * 2) + 1]
        
        # Modify first pixel (stores first 4 bits of character)
        new_pix1 = []
        for j in range(4):
            new_pix1.append(set_LSB(pix1[j], char_binary[j]))
        
        # Modify second pixel (stores last 4 bits of character)
        new_pix2 = []
        for j in range(4):
            new_pix2.append(set_LSB(pix2[j], char_binary[j + 4]))
        
        new_pixels.append(tuple(new_pix1))
        new_pixels.append(tuple(new_pix2))
    
    # Keep remaining pixels unchanged
    new_pixels.extend(pixels[len(message) * 2:])
    
    # Create output image
    out_img = Image.new(img.mode, img.size)
    out_img.putdata(new_pixels)
    out_img.save(output_path)
    
    print(f"\nMessage hidden successfully!")
    print(f"Output saved to: {output_path}")
    
    return output_path

def extract_message(image_path):
    """Extract hidden message from image"""
    img = Image.open(image_path)
    pixels = list(img.getdata())
    message = ""
    
    # Read pairs of pixels
    for i in range(0, len(pixels) - 1, 2):
        pix1 = pixels[i]
        pix2 = pixels[i + 1]
        
        # Extract 8 bits (4 from each pixel)
        byte = "0b"
        for channel in pix1:
            byte += get_LSB(channel)
        for channel in pix2:
            byte += get_LSB(channel)
        
        # Check for null terminator
        if byte == "0b00000000":
            break
        
        message += chr(int(byte, 2))
    
    return message

if __name__ == "__main__":
    # Input/output files
    input_image = "compay_logo.png"  # Note: filename has typo in original
    output_image = "company_logo_stego.png"
    secret_message = "TARGET:192.168.1.50"
    
    print("=" * 50)
    print("Part A - Manual LSB Steganography")
    print("=" * 50)
    
    # Hide the message
    hide_message_in_pixels(input_image, secret_message, output_image)
    
    # Verify by extracting
    print("\n" + "=" * 50)
    print("Verification - Extracting hidden message:")
    print("=" * 50)
    extracted = extract_message(output_image)
    print(f"Extracted message: '{extracted}'")
    
    if extracted == secret_message:
        print("\n✓ SUCCESS: Message hidden and extracted correctly!")
    else:
        print("\n✗ ERROR: Extracted message doesn't match!")
