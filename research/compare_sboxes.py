#!/usr/bin/env python3
"""
Compare AhnLab extracted S-boxes with standard SEED S-boxes
"""

# Standard SEED S-boxes from RFC 4269 (first 8 values of each)
STANDARD_SS0 = [
    0x2989A1A8,
    0x05858184,
    0x16C6D2D4,
    0x13C3D0D3,
    0x14145450,
    0x1D0D1C11,
    0x2C8CACA0,
    0x25052421,
]

STANDARD_SS1 = [
    0x38383008,
    0xE828E0C8,
    0x2D2C210D,
    0x26A4A286,
    0x0FCCC3CF,
    0x1EDCD2CE,
    0x33B0B383,
    0x38B8B088,
]

STANDARD_SS2 = [
    0xA1A82989,
    0x81840585,
    0xD2D416C6,
    0xD3D013C3,
    0x54501414,
    0x111C0D1D,
    0xA0AC2C8C,
    0x21242505,
]

STANDARD_SS3 = [
    0x08303838,
    0xC8E028E8,
    0x0D212D2C,
    0x86A426A4,
    0xCFC30FCC,
    0xDCD21EDC,
    0x83B333B0,
    0x88B038B8,
]

# Extracted from r2 (converting little-endian hex to big-endian 32-bit values)
# 0x086286a0: a8a1 8929 8481 8505 d4d2 c616 d0d3 c313
AHNLAB_SS0 = [
    0x2989A1A8,  # a8a1 8929 -> 0x2989A1A8
    0x05858184,  # 8481 8505 -> 0x05858184 (corrected)
    0x16C6D2D4,  # d4d2 c616 -> 0x16C6D2D4
    0x13C3D0D3,  # d0d3 c313 -> 0x13C3D0D3
    0x14145450,  # 5450 4414 -> 0x14145450
    0x1D0D1C11,  # 1c11 0d1d -> 0x1D0D1C11
    0x2C8CACA0,  # aca0 8c2c -> 0x2C8CACA0
    0x25052421,  # 2421 0525 -> 0x25052421
]

# 0x08628aa0: 3008 3838 e0c8 28e8 210d 2d2c a286 26a4
AHNLAB_SS1 = [
    0x38383008,  # 3008 3838 -> 0x38383008
    0xE828E0C8,  # e0c8 28e8 -> 0xE828E0C8
    0x2D2C210D,  # 210d 2d2c -> 0x2D2C210D
    0x26A4A286,  # a286 26a4 -> 0x26A4A286
    0x0FCCC3CF,  # c3cf 0fcc -> 0x0FCCC3CF
    0x1EDCD2CE,  # d2ce 1edc -> 0x1EDCD2CE
    0x33B0B383,  # b383 33b0 -> 0x33B0B383
    0x38B8B088,  # b088 38b8 -> 0x38B8B088
]

# 0x08628ea0: 8929 a8a1 8505 8481 c616 d4d2 c313 d0d3
AHNLAB_SS2 = [
    0xA1A82989,  # 8929 a8a1 -> 0xA1A82989
    0x81840585,  # 8505 8481 -> 0x81840585 (corrected)
    0xD2D416C6,  # c616 d4d2 -> 0xD2D416C6
    0xD3D013C3,  # c313 d0d3 -> 0xD3D013C3
    0x54501414,  # 4414 5450 -> 0x54501414
    0x111C0D1D,  # 0d1d 1c11 -> 0x111C0D1D
    0xA0AC2C8C,  # 8c2c aca0 -> 0xA0AC2C8C
    0x21242505,  # 0525 2421 -> 0x21242505
]

# 0x086292a0: 3838 3008 28e8 e0c8 2d2c 210d 26a4 a286
AHNLAB_SS3 = [
    0x08303838,  # 3838 3008 -> 0x08303838
    0xC8E028E8,  # 28e8 e0c8 -> 0xC8E028E8
    0x0D212D2C,  # 2d2c 210d -> 0x0D212D2C
    0x86A426A4,  # 26a4 a286 -> 0x86A426A4
    0xCFC30FCC,  # 0fcc c3cf -> 0xCFC30FCC
    0xDCD21EDC,  # 1edc d2ce -> 0xDCD21EDC
    0x83B333B0,  # 33b0 b383 -> 0x83B333B0
    0x88B038B8,  # 38b8 b088 -> 0x88B038B8
]


def compare_sboxes():
    """Compare AhnLab S-boxes with standard SEED S-boxes"""

    print("Comparing AhnLab S-boxes with Standard SEED S-boxes")
    print("=" * 60)

    sboxes = [
        ("SS0", STANDARD_SS0, AHNLAB_SS0),
        ("SS1", STANDARD_SS1, AHNLAB_SS1),
        ("SS2", STANDARD_SS2, AHNLAB_SS2),
        ("SS3", STANDARD_SS3, AHNLAB_SS3),
    ]

    total_matches = 0
    total_entries = 0

    for name, standard, ahnlab in sboxes:
        print(f"\n{name} Comparison:")
        print("-" * 20)

        matches = 0
        for i, (std, ahn) in enumerate(zip(standard, ahnlab)):
            match = "✓" if std == ahn else "✗"
            print(f"  [{i}] Standard: 0x{std:08X} | AhnLab: 0x{ahn:08X} {match}")
            if std == ahn:
                matches += 1

        print(
            f"  Matches: {matches}/{len(standard)} ({matches / len(standard) * 100:.1f}%)"
        )
        total_matches += matches
        total_entries += len(standard)

    print(
        f"\nOverall Match Rate: {total_matches}/{total_entries} ({total_matches / total_entries * 100:.1f}%)"
    )

    if total_matches == total_entries:
        print("\n[+] IDENTICAL: AhnLab uses standard SEED S-boxes")
    elif total_matches > total_entries * 0.8:
        print(
            "\n[~] SIMILAR: AhnLab uses mostly standard SEED with minor modifications"
        )
    else:
        print("\n[-] CUSTOM: AhnLab uses significantly different S-boxes")

    return total_matches / total_entries


if __name__ == "__main__":
    match_rate = compare_sboxes()
