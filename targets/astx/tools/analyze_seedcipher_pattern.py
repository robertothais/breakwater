#!/usr/bin/env python3
"""
Analyze the pattern between our CBC calculation and seedCipher output
to reverse engineer what seedCipher actually does
"""

def analyze_block_differences():
    """Compare our CBC output with seedCipher output block by block"""
    
    # Our manual CBC results
    manual_cbc = [
        bytes.fromhex("25e4e28faebf37952cfedabf26350ad8"),
        bytes.fromhex("963497809054b5adcd54e0e37068228a"),  
        bytes.fromhex("5d00278d8aa37febf4ef56dbe2d3560c"),
        bytes.fromhex("dfe1c5f71db424abb5b06f8055fd9da9")
    ]
    
    # seedCipher actual output
    seedcipher_output = [
        bytes.fromhex("fcc7e8bd31ca6da42cbd688a2ded6f93"),
        bytes.fromhex("952cf230a78cdaa6933a11487f40d3e7"),
        bytes.fromhex("9fbbf6d4117fe36ef11af41d252ac408"),
        bytes.fromhex("609269fdc1d08eabb80e9e88efa1aaa9")
    ]
    
    print("BLOCK-BY-BLOCK ANALYSIS")
    print("=" * 60)
    
    for block_num in range(4):
        print(f"\nBlock {block_num + 1}:")
        print(f"  Manual CBC:     {manual_cbc[block_num].hex()}")
        print(f"  seedCipher:     {seedcipher_output[block_num].hex()}")
        
        # XOR the two to see if there's a pattern
        xor_result = bytes(a ^ b for a, b in zip(manual_cbc[block_num], seedcipher_output[block_num]))
        print(f"  XOR difference: {xor_result.hex()}")
        
        # Check for byte-level patterns
        print("  Byte differences:")
        for i in range(16):
            manual_byte = manual_cbc[block_num][i]
            seed_byte = seedcipher_output[block_num][i]
            xor_byte = manual_byte ^ seed_byte
            print(f"    {i:2d}: {manual_byte:02x} -> {seed_byte:02x} (XOR: {xor_byte:02x})")

def check_for_simple_transformations():
    """Check if seedCipher applies simple transformations"""
    
    # Test data from first block
    manual = bytes.fromhex("25e4e28faebf37952cfedabf26350ad8")
    seedcipher = bytes.fromhex("fcc7e8bd31ca6da42cbd688a2ded6f93")
    
    print("\n" + "=" * 60)
    print("CHECKING SIMPLE TRANSFORMATIONS")
    print("=" * 60)
    
    # Check if it's a simple XOR with a constant
    xor_pattern = bytes(a ^ b for a, b in zip(manual, seedcipher))
    print(f"XOR pattern: {xor_pattern.hex()}")
    
    # Check if the XOR pattern repeats
    unique_xor_bytes = set(xor_pattern)
    print(f"Unique XOR bytes: {len(unique_xor_bytes)} ({[hex(b) for b in sorted(unique_xor_bytes)]})")
    
    # Check if it's byte swap
    print(f"\nByte swap patterns:")
    print(f"  Original: {manual.hex()}")
    print(f"  Reversed: {manual[::-1].hex()}")
    print(f"  seedCipher: {seedcipher.hex()}")
    
    # Check if it's some kind of shift
    for shift in range(1, 16):
        shifted = manual[shift:] + manual[:shift]
        if shifted == seedcipher:
            print(f"  Found shift by {shift} bytes!")
            break
    
    # Check bitwise operations
    print(f"\nBitwise operations:")
    print(f"  NOT manual:     {bytes(~b & 0xFF for b in manual).hex()}")
    print(f"  Manual << 1:    {bytes((b << 1) & 0xFF for b in manual).hex()}")
    print(f"  Manual >> 1:    {bytes(b >> 1 for b in manual).hex()}")

def analyze_iv_usage():
    """Check if seedCipher uses IV differently"""
    
    print("\n" + "=" * 60)
    print("ANALYZING IV USAGE")
    print("=" * 60)
    
    # Our understanding: raw_decrypt XOR IV = manual CBC
    raw_decrypt = bytes.fromhex("24e6e18baebf37952cfedabf26350ad8")
    iv = bytes.fromhex("01020304000000000000000000000000") 
    manual_cbc = bytes.fromhex("25e4e28faebf37952cfedabf26350ad8")
    seedcipher = bytes.fromhex("fcc7e8bd31ca6da42cbd688a2ded6f93")
    
    print("Components:")
    print(f"  Raw decrypt:    {raw_decrypt.hex()}")
    print(f"  IV:             {iv.hex()}")
    print(f"  Manual CBC:     {manual_cbc.hex()}")
    print(f"  seedCipher:     {seedcipher.hex()}")
    
    # What if seedCipher XORs raw_decrypt with something else instead of IV?
    mystery_xor = bytes(a ^ b for a, b in zip(raw_decrypt, seedcipher))
    print(f"  Mystery XOR:    {mystery_xor.hex()}")
    
    # Compare mystery XOR with IV
    iv_vs_mystery = bytes(a ^ b for a, b in zip(iv, mystery_xor))
    print(f"  IV vs Mystery:  {iv_vs_mystery.hex()}")
    
    # What if it's IV processed differently?
    print(f"\nIV transformations:")
    print(f"  IV:             {iv.hex()}")
    print(f"  IV reversed:    {iv[::-1].hex()}")
    print(f"  NOT IV:         {bytes(~b & 0xFF for b in iv).hex()}")

def check_previous_block_influence():
    """Check if seedCipher uses previous ciphertext differently"""
    
    print("\n" + "=" * 60) 
    print("CHECKING PREVIOUS BLOCK INFLUENCE")
    print("=" * 60)
    
    # Ciphertext blocks
    cipher_blocks = [
        bytes.fromhex("62c860802d8393c55ed5fea42b0107f3"),  # Block 1
        bytes.fromhex("30a26fe58fba6814077ce2da93c7e023"),  # Block 2  
        bytes.fromhex("a5a196e745472c1888d99010a6e25fd1"),  # Block 3
        bytes.fromhex("181f5893851deba0cbf15bc9cf6ee7aa")   # Block 4
    ]
    
    # Raw decrypts 
    raw_decrypts = [
        bytes.fromhex("24e6e18baebf37952cfedabf26350ad8"),  # Block 1
        bytes.fromhex("a696f8651feeddb9ca280239e3afc2a9"),  # Block 2
        # We need to calculate blocks 3 and 4...
    ]
    
    # seedCipher outputs
    seedcipher_outputs = [
        bytes.fromhex("fcc7e8bd31ca6da42cbd688a2ded6f93"),
        bytes.fromhex("952cf230a78cdaa6933a11487f40d3e7"),
        bytes.fromhex("9fbbf6d4117fe36ef11af41d252ac408"),
        bytes.fromhex("609269fdc1d08eabb80e9e88efa1aaa9")
    ]
    
    # For block 1: what does raw_decrypt need to XOR with to get seedcipher output?
    print("Block 1 analysis:")
    iv = bytes.fromhex("01020304000000000000000000000000")
    mystery_xor_1 = bytes(a ^ b for a, b in zip(raw_decrypts[0], seedcipher_outputs[0]))
    print(f"  Raw decrypt:    {raw_decrypts[0].hex()}")
    print(f"  seedCipher:     {seedcipher_outputs[0].hex()}")
    print(f"  Mystery XOR:    {mystery_xor_1.hex()}")
    print(f"  Expected IV:    {iv.hex()}")
    print(f"  IV vs Mystery:  {bytes(a ^ b for a, b in zip(iv, mystery_xor_1)).hex()}")

if __name__ == "__main__":
    analyze_block_differences()
    check_for_simple_transformations()
    analyze_iv_usage()
    check_previous_block_influence()
    
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print("Look for patterns in the output above to understand")
    print("what transformation seedCipher applies beyond standard CBC.")