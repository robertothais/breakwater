#!/usr/bin/env python3
"""
Analyze the key setup from MySeedEnDecrypt function
"""

import struct

# From the Ghidra decompilation:
# local_30 = 0x6c6e6841;  // "Ahn" + "l" 
# local_2c = 0x65536261;  // "ab" + "Se"
# local_28 = 0x74657263;  // "cret"
# local_24 = 0x79654b;    // "Key" (3 bytes)
# local_20 = 0x4030201;   // IV: [1,2,3,4]

def analyze_key_construction():
    """Decode the key construction from Ghidra hex values"""
    
    print("Analyzing MySeedEnDecrypt key setup")
    print("=" * 40)
    
    # Decode the hex values (little-endian)
    local_30 = 0x6c6e6841
    local_2c = 0x65536261  
    local_28 = 0x74657263
    local_24 = 0x79654b
    local_20 = 0x4030201
    
    # Convert to bytes (little-endian)
    key_part1 = struct.pack('<I', local_30)  # 4 bytes
    key_part2 = struct.pack('<I', local_2c)  # 4 bytes  
    key_part3 = struct.pack('<I', local_28)  # 4 bytes
    key_part4 = struct.pack('<I', local_24)  # 4 bytes (but only 3 used + 1 null)
    iv_bytes = struct.pack('<I', local_20)   # 4 bytes
    
    print(f"local_30 = 0x{local_30:08x} -> {key_part1} -> '{key_part1.decode('ascii', errors='ignore')}'")
    print(f"local_2c = 0x{local_2c:08x} -> {key_part2} -> '{key_part2.decode('ascii', errors='ignore')}'") 
    print(f"local_28 = 0x{local_28:08x} -> {key_part3} -> '{key_part3.decode('ascii', errors='ignore')}'")
    print(f"local_24 = 0x{local_24:08x} -> {key_part4} -> '{key_part4.decode('ascii', errors='ignore')}'")
    print(f"local_20 = 0x{local_20:08x} -> {iv_bytes} -> IV: {list(iv_bytes)}")
    
    # Reconstruct the full 16-byte key
    full_key = key_part1 + key_part2 + key_part3 + key_part4
    print(f"\nReconstructed key: '{full_key.decode('ascii', errors='ignore')}'")
    print(f"Key length: {len(full_key)} bytes")
    print(f"Key hex: {full_key.hex()}")
    
    # Check against our current implementation
    current_key = b"AhnlabSecretKey\x00"
    print(f"\nCurrent key: '{current_key.decode('ascii', errors='ignore')}'") 
    print(f"Current hex: {current_key.hex()}")
    print(f"Keys match: {full_key == current_key}")
    
    # IV analysis - need to extend 4 bytes to 16 bytes
    iv_4bytes = iv_bytes
    iv_16bytes = iv_4bytes + b'\x00' * 12  # Pad with zeros
    print(f"\nIV (4 bytes): {list(iv_4bytes)}")
    print(f"IV (16 bytes): {list(iv_16bytes)}")
    print(f"IV hex: {iv_16bytes.hex()}")
    
    return full_key, iv_16bytes

def analyze_key_schedule_size():
    """Analyze the 112-byte key schedule"""
    
    print("\nKey Schedule Analysis")
    print("=" * 30)
    
    print("Standard SEED:")
    print("  - 16 rounds") 
    print("  - 2 round keys per round = 32 total round keys")
    print("  - 32 * 4 bytes = 128 bytes")
    
    print("\nAhnLab SEED:")
    print("  - ? rounds")
    print("  - 112 bytes total")
    print("  - 112 / 4 = 28 round keys")
    print("  - 28 / 2 = 14 rounds (if 2 keys per round)")
    print("  - OR different key schedule structure")
    
    print("\nImplications:")
    print("  - AhnLab might use 14 rounds instead of 16")
    print("  - OR they use a different key arrangement")
    print("  - Standard SEED library expects 128 bytes")
    print("  - Need custom implementation or library modification")

if __name__ == "__main__":
    key, iv = analyze_key_construction()
    analyze_key_schedule_size()
    
    print(f"\nNext steps:")
    print(f"1. Confirm key/IV match our current implementation")
    print(f"2. Investigate if SEED library can handle 112-byte schedule")  
    print(f"3. Consider implementing custom SEED with 14 rounds")