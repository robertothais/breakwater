#!/usr/bin/env python3
"""
Step-by-step explanation of how I analyzed the seedKeyExpand function
"""

def explain_step_by_step():
    print("Step-by-Step Analysis of seedKeyExpand Function")
    print("=" * 55)
    
    print("\n1. FUNCTION SIGNATURE ANALYSIS")
    print("-" * 35)
    print("void seedKeyExpand(uint *expanded_key_schedule, int source_key_length, int param_3)")
    print()
    print("What this tells us:")
    print("  - expanded_key_schedule: Output buffer (the 112-byte local_a0)")
    print("  - source_key_length: Input key length (0x10 = 16 bytes)")
    print("  - param_3: Pointer to source key data (&local_30)")
    
    print("\n2. INITIAL KEY COPY LOOP")
    print("-" * 30)
    print("Code:")
    print("  for (local_24 = 0; local_24 < 0x10; local_24 = local_24 + 1) {")
    print("    if (local_24 < source_key_length) {")
    print("      *(undefined1 *)(local_24 + (int)expanded_key_schedule) = *(undefined1 *)(param_3 + local_24);")
    print("    }")
    print("    else {")
    print("      *(undefined1 *)(local_24 + (int)expanded_key_schedule) = 0;")
    print("    }")
    print("  }")
    print()
    print("What this does:")
    print("  - Loops from 0 to 0x10 (16) bytes")
    print("  - Copies source key bytes to positions 0-15")
    print("  - Zero-pads if source key < 16 bytes")
    print("  - Result: First 16 bytes of expanded_key_schedule = original key")
    
    print("\n3. IDENTIFYING THE PATTERN")
    print("-" * 32)
    print("After the loop, I see repeated blocks like:")
    print("  expanded_key_schedule[4] = [S-box operations with 0x61c88647]")
    print("  expanded_key_schedule[5] = [S-box operations with 0x9e3779b9]")
    print("  expanded_key_schedule[6] = [S-box operations with 0xc3910c8d]")
    print("  expanded_key_schedule[7] = [S-box operations with 0x3c6ef373]")
    print("  ...")
    print()
    print("Pattern recognition:")
    print("  - Each pair of positions gets assigned together")
    print("  - Each uses different magic constants")
    print("  - S-box operations are identical structure")
    
    print("\n4. COUNTING THE ASSIGNMENTS")
    print("-" * 33)
    assignments = [
        (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15),
        (16, 17), (18, 19), (20, 21), (22, 23), (24, 25), (26, 27)
    ]
    
    print("Manually counting each assignment:")
    for i, (pos1, pos2) in enumerate(assignments, 1):
        print(f"  Assignment {i:2d}: positions [{pos1:2d}, {pos2:2d}]")
    
    print(f"\nTotal assignments: {len(assignments)}")
    print(f"Total round keys: {len(assignments) * 2} = {len(assignments) * 2}")
    print(f"Highest position: {max(max(pair) for pair in assignments)} (0x{max(max(pair) for pair in assignments):02x})")
    
    print("\n5. CALCULATING BUFFER SIZE")
    print("-" * 31)
    print("Buffer size calculation:")
    print(f"  - Original key: 16 bytes (positions 0-15)")
    print(f"  - Round keys: {len(assignments)} pairs × 2 × 4 bytes = {len(assignments) * 2 * 4} bytes")
    print(f"  - Total: 16 + {len(assignments) * 2 * 4} = {16 + len(assignments) * 2 * 4} bytes")
    print(f"  - This matches the 112-byte local_a0 buffer!")
    
    print("\n6. EXTRACTING MAGIC CONSTANTS")
    print("-" * 35)
    print("From the Ghidra code, I extracted constants by looking at each assignment:")
    
    constants_from_code = [
        ("positions 4,5", "0x61c88647", "0x9e3779b9"),
        ("positions 6,7", "0xc3910c8d", "0x3c6ef373"),
        ("positions 8,9", "0x8722191a", "0x78dde6e6"),
        # ... (showing just first few for explanation)
    ]
    
    for pos, c1, c2 in constants_from_code:
        print(f"  {pos}: {c1}, {c2}")
    print("  ... (continuing for all 12 pairs)")
    
    print("\n7. RECOGNIZING THE S-BOX PATTERN")
    print("-" * 38)
    print("Each assignment uses this pattern:")
    print("  expanded_key_schedule[X] =")
    print("       *(uint *)(&DAT_086286a0 + (var & 0xff) * 4) ^")
    print("       *(uint *)(&DAT_08628aa0 + (var >> 8 & 0xff) * 4) ^")
    print("       *(uint *)(&DAT_08628ea0 + (var >> 0x10 & 0xff) * 4) ^")
    print("       *(uint *)(&DAT_086292a0 + (var >> 0x18) * 4);")
    print()
    print("This is standard SEED S-box lookup:")
    print("  - DAT_086286a0 = S-box 0 (SS0)")
    print("  - DAT_08628aa0 = S-box 1 (SS1)")
    print("  - DAT_08628ea0 = S-box 2 (SS2)")
    print("  - DAT_086292a0 = S-box 3 (SS3)")
    print("  - Takes 4 bytes of input, does 4 S-box lookups, XORs result")
    
    print("\n8. DERIVING ROUND COUNT")
    print("-" * 28)
    print("SEED algorithm logic:")
    print("  - SEED is a Feistel cipher")
    print("  - Each round needs 2 round keys (left and right)")
    print("  - We found 24 round keys total")
    print("  - 24 round keys ÷ 2 keys per round = 12 rounds")
    print("  - Standard SEED uses 16 rounds (32 round keys)")
    print("  - Therefore: AhnLab uses custom 12-round SEED")
    
    print("\n9. COMPARISON WITH STANDARD")
    print("-" * 35)
    print("Standard SEED (RFC 4269):")
    print("  - 16 rounds")
    print("  - 32 round keys")
    print("  - 128-byte key schedule")
    print("  - Golden ratio constants")
    print()
    print("AhnLab SEED (from analysis):")
    print("  - 12 rounds")
    print("  - 24 round keys")
    print("  - 112-byte key schedule")
    print("  - Custom constant sequence")
    print("  - Same S-boxes")
    
    print("\n10. VALIDATION")
    print("-" * 15)
    print("How I validated this analysis:")
    print("  ✓ 112 bytes matches local_a0 buffer size")
    print("  ✓ S-box addresses match our extracted S-boxes")
    print("  ✓ Key structure matches MySeedEnDecrypt usage")
    print("  ✓ Math adds up: 16 + 24*4 = 112")
    print("  ✓ Explains why standard SEED library fails")


def show_constant_extraction():
    print("\n\nDETAILED CONSTANT EXTRACTION EXAMPLE")
    print("=" * 45)
    
    print("Let me show exactly how I extracted the first constant pair:")
    print()
    print("From Ghidra code:")
    print("  uVar1 = uVar10 + uVar8 + 0x61c88647;")
    print("  uVar2 = (uVar7 - uVar9) + 0x9e3779b9;")
    print("  expanded_key_schedule[4] = [S-box operations using uVar1]")
    print("  expanded_key_schedule[5] = [S-box operations using uVar2]")
    print()
    print("Extraction process:")
    print("  1. I see 0x61c88647 added to create uVar1")
    print("  2. uVar1 is used in S-box operations for position 4")
    print("  3. I see 0x9e3779b9 added to create uVar2")
    print("  4. uVar2 is used in S-box operations for position 5")
    print("  5. Therefore: Round 1 uses constants (0x61c88647, 0x9e3779b9)")
    print()
    print("I repeated this for all 12 pairs to get the complete constant table.")


if __name__ == "__main__":
    explain_step_by_step()
    show_constant_extraction()
    
    print("\n\nSUMMARY")
    print("=" * 10)
    print("The key insight was recognizing that:")
    print("1. The function systematically assigns pairs of positions")
    print("2. Each assignment follows the same S-box pattern")
    print("3. The constants are used sequentially")
    print("4. The total count reveals the custom round structure")
    print()
    print("This methodical analysis of the decompiled code revealed")
    print("that AhnLab uses a 12-round SEED variant, not standard 16-round SEED.")