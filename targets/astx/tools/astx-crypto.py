#!/usr/bin/env python3

import ctypes
from pathlib import Path

# Load the astx-ui binary as a library
binary_path = Path(__file__).parent.parent / "unpacked/rootfs/opt/AhnLab/ASTx/astx-ui"
lib = ctypes.CDLL(str(binary_path))

# Get the XorDecryption function by name
XorDecryption = lib.XorDecryption
XorDecryption.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
XorDecryption.restype = None

def xor_decrypt(data: bytes, key: bytes = b"KEY2ENCRYPT&DECRYPT") -> bytes:
    """Decrypt data using ASTx's XorDecryption function"""
    # Create mutable buffer for in-place decryption
    buffer = ctypes.create_string_buffer(data)
    XorDecryption(buffer, len(data), key)
    return buffer.raw[:len(data)]

if __name__ == "__main__":
    # Test with sample data
    test_data = b"Hello World!"
    print(f"Original: {test_data}")
    
    encrypted = xor_decrypt(test_data)
    print(f"Encrypted: {encrypted.hex()}")
    
    decrypted = xor_decrypt(encrypted)
    print(f"Decrypted: {decrypted}")