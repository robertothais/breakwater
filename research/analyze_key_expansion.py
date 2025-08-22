#!/usr/bin/env python3
"""
Analyze AhnLab's seedKeyExpand function from Ghidra decompilation
"""

def analyze_key_expansion():
    """
    Analyze the seedKeyExpand function structure
    """
    print("AhnLab seedKeyExpand Analysis")
    print("=" * 40)
    
    print("Function signature:")
    print("void seedKeyExpand(uint *expanded_key_schedule, int source_key_length, int param_3)")
    print()
    
    print("Key expansion structure:")
    print("1. First loop (0x00-0x0F): Copy source key + zero padding")
    print("   - Copies source_key_length bytes from param_3")
    print("   - Zero-pads to 16 bytes")
    print()
    
    print("2. Key schedule generation (0x04-0x1B):")
    print("   - Generates positions 4-27 (24 round keys)")
    print("   - Each pair uses S-box lookups with specific constants")
    print("   - Total: 16 bytes original + 24*4 = 112 bytes")
    print()
    
    # Map out the constants used
    constants = [
        (4, 5, "0x61c88647", "0x9e3779b9"),
        (6, 7, "0xc3910c8d", "0x3c6ef373"), 
        (8, 9, "0x8722191a", "0x78dde6e6"),
        (10, 11, "0xe443234", "0xf1bbcdcc"),
        (12, 13, "0x1c886467", "0xe3779b99"),
        (14, 15, "0x3910c8cd", "0xc6ef3733"),
        (16, 17, "0x72219199", "0x8dde6e67"),
        (18, 19, "0xe4432331", "0x1bbcdccf"),
        (20, 21, "0xc8864662", "0x3779b99e"),
        (22, 23, "0x910c8cc4", "0x6ef3733c"),
        (24, 25, "0x22191988", "0xdde6e678"),
        (26, 27, "0x4432330f", "0xbbcdccf1")
    ]
    
    print("Round constants analysis:")
    for i, (pos1, pos2, const1, const2) in enumerate(constants):
        print(f"Round {i+1:2d}: positions [{pos1:2d},{pos2:2d}] -> {const1}, {const2}")
    
    print(f"\nTotal rounds: {len(constants)}")
    print(f"Total round keys: {len(constants) * 2} = 24")
    print(f"Key schedule size: 16 + 24*4 = 112 bytes")
    
    print("\nS-box addresses:")
    print("  DAT_086286a0 -> SS0")
    print("  DAT_08628aa0 -> SS1") 
    print("  DAT_08628ea0 -> SS2")
    print("  DAT_086292a0 -> SS3")
    
    print("\nKey differences from standard SEED:")
    print("  Standard SEED: 16 rounds, 32 round keys, 128 bytes")
    print("  AhnLab SEED:   12 rounds, 24 round keys, 112 bytes")
    
    return constants


def analyze_constants():
    """
    Analyze the magic constants used in key expansion
    """
    print("\nMagic Constants Analysis")
    print("=" * 30)
    
    # Extract all constants from the pairs
    all_constants = [
        0x61c88647, 0x9e3779b9, 0xc3910c8d, 0x3c6ef373,
        0x8722191a, 0x78dde6e6, 0xe443234, 0xf1bbcdcc,
        0x1c886467, 0xe3779b99, 0x3910c8cd, 0xc6ef3733,
        0x72219199, 0x8dde6e67, 0xe4432331, 0x1bbcdccf,
        0xc8864662, 0x3779b99e, 0x910c8cc4, 0x6ef3733c,
        0x22191988, 0xdde6e678, 0x4432330f, 0xbbcdccf1
    ]
    
    print("Looking for patterns in constants:")
    
    # Check for golden ratio constant (common in SEED)
    golden_ratio = 0x9e3779b9
    print(f"Golden ratio constant 0x9e3779b9 found: {golden_ratio in all_constants}")
    
    # Check for relationships between constants
    differences = []
    for i in range(0, len(all_constants), 2):
        if i+1 < len(all_constants):
            diff = all_constants[i+1] - all_constants[i]
            differences.append(diff)
            print(f"Const pair {i//2+1}: 0x{all_constants[i]:08x} -> 0x{all_constants[i+1]:08x} (diff: 0x{diff:08x})")
    
    print(f"\nUnique differences: {len(set(differences))}")
    if len(set(differences)) == 1:
        print(f"All differences are identical: 0x{differences[0]:08x}")
    
    return all_constants


def compare_with_standard_seed():
    """
    Compare with standard SEED key expansion
    """
    print("\nComparison with Standard SEED")
    print("=" * 35)
    
    print("Standard SEED key expansion:")
    print("  - Uses 32 round constants")
    print("  - Golden ratio based: 0x9e3779b9")
    print("  - Generates 128 bytes (32 round keys)")
    
    print("\nAhnLab modifications:")
    print("  - Uses 24 round constants")
    print("  - Custom constant sequence")
    print("  - Generates 112 bytes (24 round keys)")
    print("  - Same S-box structure")
    print("  - Same bit operations pattern")
    
    print("\nConclusion:")
    print("  This is a CUSTOM SEED variant with:")
    print("  - Fewer rounds (12 vs 16)")
    print("  - Custom round constants")
    print("  - Standard S-boxes")


if __name__ == "__main__":
    constants = analyze_key_expansion()
    all_consts = analyze_constants()
    compare_with_standard_seed()
    
    print(f"\nNext steps:")
    print(f"1. Implement custom key expansion with these exact constants")
    print(f"2. Use standard S-boxes for F-function")
    print(f"3. Implement 12-round Feistel structure")
    print(f"4. Test against astxcfg.dat")