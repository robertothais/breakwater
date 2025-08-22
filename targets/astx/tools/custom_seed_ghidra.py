#!/usr/bin/env python2
# Ghidra script using the working conventions
# Based on the version that successfully ran without hanging

import struct
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor

print "=" * 60
print "Testing AhnLab SEED Implementation"
print "=" * 60

# Create emulator and monitor
emu = EmulatorHelper(currentProgram)
monitor = ConsoleTaskMonitor()

# Multiple test keys for validation
test_keys = [
    ([0x41, 0x68, 0x6E, 0x6C, 0x61, 0x62, 0x53, 0x65,
      0x63, 0x72, 0x65, 0x74, 0x4B, 0x65, 0x79, 0x00], "AhnlabSecretKey"),
    ([0x00] * 16, "all zeros"),
    ([0xFF] * 16, "all ones"),
    ([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10], "sequential"),
    ([0xAA] * 16, "repeated 0xAA"),
]

# Allocate memory regions (use low addresses that work)
KEY_ADDR = 0x1000
KEY_SCHEDULE_ADDR = 0x2000
DATA_ADDR = 0x3000
OUTPUT_ADDR = 0x4000
STACK_ADDR = 0x10000

# Set up stack
emu.writeRegister("ESP", STACK_ADDR)

print "\n1. Testing seedKeyExpand with multiple keys"

# Test all keys
for key_idx, (test_key, key_desc) in enumerate(test_keys):
    print "\n   Key %d (%s):" % (key_idx + 1, key_desc)
    print "   Input key:", "".join("%02x" % b for b in test_key)

    # Write test key to memory
    for i, b in enumerate(test_key):
        emu.writeMemoryValue(toAddr(KEY_ADDR + i), 1, b)

    # Find seedKeyExpand function (only once)
    if key_idx == 0:
        func_manager = currentProgram.getFunctionManager()
        seedKeyExpand = None

        for func in func_manager.getFunctions(True):
            name = func.getName()
            # Also check by address if name search fails
            if "seedKeyExpand" in name or "KeyExpand" in name or str(func.getEntryPoint()) == "08105c2d":
                seedKeyExpand = func
                print "   Found", name, "at", func.getEntryPoint()
                break

        if not seedKeyExpand:
            # Try direct address
            addr = toAddr(0x08105c2d)
            seedKeyExpand = func_manager.getFunctionAt(addr)
            if seedKeyExpand:
                print "   Found seedKeyExpand at", addr
            else:
                print "   WARNING: Could not find seedKeyExpand, using address 0x08105c2d"

    if seedKeyExpand or True:  # Continue even if not found, use the address
        entry = seedKeyExpand.getEntryPoint() if seedKeyExpand else toAddr(0x08105c2d)

        # Reset stack
        emu.writeRegister("ESP", STACK_ADDR)

        # Set up parameters on stack (stdcall convention)
        # IMPORTANT: Include return address!
        emu.writeStackValue(0, 4, 0x99999999)  # Return address
        emu.writeStackValue(4, 4, KEY_SCHEDULE_ADDR)  # Output buffer
        emu.writeStackValue(8, 4, 16)  # Key length
        emu.writeStackValue(12, 4, KEY_ADDR)  # Key data

        print "   Calling seedKeyExpand..."
        # Call the function
        emu.run(entry, None, monitor)

        # Read expanded key (112 bytes)
        print "   Expanded key schedule (hex):"
        for i in range(0, 112, 16):
            row = []
            for j in range(16):
                if i + j < 112:
                    val = emu.readMemoryByte(toAddr(KEY_SCHEDULE_ADDR + i + j))
                    row.append("%02x" % (val & 0xFF))
            print "     " + " ".join(row)

print "\n2. Testing seedDecrypt"

# IMPORTANT: Reset to AhnlabSecretKey for decrypt tests
print "\n   Resetting to AhnlabSecretKey for decrypt tests..."
ahnlab_key = [0x41, 0x68, 0x6E, 0x6C, 0x61, 0x62, 0x53, 0x65,
              0x63, 0x72, 0x65, 0x74, 0x4B, 0x65, 0x79, 0x00]

# Write AhnlabSecretKey to memory
for i, b in enumerate(ahnlab_key):
    emu.writeMemoryValue(toAddr(KEY_ADDR + i), 1, b)

# Re-expand the key schedule with AhnlabSecretKey
entry = seedKeyExpand.getEntryPoint() if seedKeyExpand else toAddr(0x08105c2d)
emu.writeRegister("ESP", STACK_ADDR)
emu.writeStackValue(0, 4, 0x99999999)  # Return address
emu.writeStackValue(4, 4, KEY_SCHEDULE_ADDR)  # Output buffer
emu.writeStackValue(8, 4, 16)  # Key length
emu.writeStackValue(12, 4, KEY_ADDR)  # Key data
emu.run(entry, None, monitor)

print "   Using AhnlabSecretKey schedule for all decrypt tests"

# Test vectors - multiple blocks to verify
test_blocks = [
    ("62c860802d8393c55ed5fea42b0107f3", "astxcfg.dat block 1"),
    ("00000000000000000000000000000000", "all zeros"),
    ("ffffffffffffffffffffffffffffffff", "all ones"),
    ("30a26fe58fba6814077ce2da93c7e023", "astxcfg.dat block 2"),
    ("0123456789abcdef0123456789abcdef", "alternating pattern"),
    ("deadbeefcafebabe1234567890abcdef", "mixed hex values"),
    ("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "repeated 0xa5"),
    ("5555555555555555aaaaaaaaaaaaaaaa", "0x55/0xaa pattern"),
]

# Find seedDecrypt
seedDecrypt = None
for func in func_manager.getFunctions(True):
    name = func.getName()
    if "seedDecrypt" in name or ("Decrypt" in name and "seed" in name.lower()) or str(func.getEntryPoint()) == "08104f66":
        seedDecrypt = func
        print "   Found", name, "at", func.getEntryPoint()
        break

if not seedDecrypt:
    addr = toAddr(0x08104f66)
    seedDecrypt = func_manager.getFunctionAt(addr)
    if seedDecrypt:
        print "   Found seedDecrypt at", addr
    else:
        print "   WARNING: Could not find seedDecrypt, using address 0x08104f66"

if seedDecrypt or True:
    entry = seedDecrypt.getEntryPoint() if seedDecrypt else toAddr(0x08104f66)

    for test_hex, description in test_blocks:
        print "\n   Testing:", description
        print "   Input block:", test_hex

        # Convert hex string to bytes and write to memory
        for i in range(16):
            b = int(test_hex[i*2:i*2+2], 16)
            emu.writeMemoryValue(toAddr(DATA_ADDR + i), 1, b)

        # Clear output area
        for i in range(16):
            emu.writeMemoryValue(toAddr(OUTPUT_ADDR + i), 1, 0)

        # Reset ESP
        emu.writeRegister("ESP", STACK_ADDR)

        # Set up parameters
        # seedDecrypt modifies in place, so pass data address as both input and output
        emu.writeStackValue(0, 4, 0x99999999)  # Return address
        emu.writeStackValue(4, 4, DATA_ADDR)  # Data to decrypt (in/out)
        emu.writeStackValue(8, 4, KEY_SCHEDULE_ADDR)  # Key schedule

        # Call the function
        emu.run(entry, None, monitor)

        # Read decrypted data
        result = []
        for i in range(16):
            val = emu.readMemoryByte(toAddr(DATA_ADDR + i))
            result.append("%02x" % (val & 0xFF))
        print "   Output block:", "".join(result)

print "\n3. Testing CBC mode on full astxcfg.dat"
print "   " + "-" * 40

# All 4 blocks of current astxcfg.dat file
astx_blocks = [
    "62c860802d8393c55ed5fea42b0107f3",
    "30a26fe58fba6814077ce2da93c7e023",
    "a5a196e745472c1888d99010a6e25fd1",
    "181f5893851deba0cbf15bc9cf6ee7aa"
]

# Set up IV from MySeedEnDecrypt: local_20=0x4030201, others=0
# In little-endian: 01 02 03 04 00 00 00 00 00 00 00 00 00 00 00 00
IV_ADDR = 0x5000
iv_bytes = [0x01, 0x02, 0x03, 0x04] + [0x00] * 12
for i, b in enumerate(iv_bytes):
    emu.writeMemoryValue(toAddr(IV_ADDR + i), 1, b)

print "   Using binary IV: 01020304000000000000000000000000"
print "   Decrypting with proper CBC chaining:"

# Manual CBC implementation
prev_cipher_addr = IV_ADDR  # Start with IV

for i, block_hex in enumerate(astx_blocks):
    print "\n   Block %d:" % (i+1)
    
    # Write ciphertext block to memory
    for j in range(16):
        b = int(block_hex[j*2:j*2+2], 16)
        emu.writeMemoryValue(toAddr(DATA_ADDR + j), 1, b)

    # Copy ciphertext to temp location for later use
    TEMP_CIPHER_ADDR = 0x6000
    for j in range(16):
        val = emu.readMemoryByte(toAddr(DATA_ADDR + j))
        emu.writeMemoryValue(toAddr(TEMP_CIPHER_ADDR + j), 1, val)

    # Reset stack and decrypt block
    emu.writeRegister("ESP", STACK_ADDR)
    emu.writeStackValue(0, 4, 0x99999999)
    emu.writeStackValue(4, 4, DATA_ADDR)
    emu.writeStackValue(8, 4, KEY_SCHEDULE_ADDR)

    entry = toAddr(0x08104f66)  # seedDecrypt
    emu.run(entry, None, monitor)

    # Read decrypted block and XOR with previous ciphertext/IV (CBC)
    plaintext = []
    for j in range(16):
        decrypted_byte = emu.readMemoryByte(toAddr(DATA_ADDR + j))
        prev_byte = emu.readMemoryByte(toAddr(prev_cipher_addr + j))
        plaintext_byte = (decrypted_byte ^ prev_byte) & 0xFF
        plaintext.append("%02x" % plaintext_byte)

    print "     Decrypted: " + "".join(plaintext)
    
    # Update prev_cipher to current ciphertext for next iteration
    prev_cipher_addr = TEMP_CIPHER_ADDR

print "\n4. Testing seedCipher function directly"
print "   " + "-" * 40

# Test seedCipher with same astxcfg.dat data to see what it actually produces
print "\n   Setting up seedCipher test with astxcfg.dat data..."

# Use the same astx_blocks data
astx_data = [
    0x62, 0xc8, 0x60, 0x80, 0x2d, 0x83, 0x93, 0xc5, 0x5e, 0xd5, 0xfe, 0xa4, 0x2b, 0x01, 0x07, 0xf3,
    0x30, 0xa2, 0x6f, 0xe5, 0x8f, 0xba, 0x68, 0x14, 0x07, 0x7c, 0xe2, 0xda, 0x93, 0xc7, 0xe0, 0x23,
    0xa5, 0xa1, 0x96, 0xe7, 0x45, 0x47, 0x2c, 0x18, 0x88, 0xd9, 0x90, 0x10, 0xa6, 0xe2, 0x5f, 0xd1,
    0x18, 0x1f, 0x58, 0x93, 0x85, 0x1d, 0xeb, 0xa0, 0xcb, 0xf1, 0x5b, 0xc9, 0xcf, 0x6e, 0xe7, 0xaa
]

# Set up memory regions for seedCipher test
SEEDCIPHER_INPUT_ADDR = 0x7000
SEEDCIPHER_OUTPUT_ADDR = 0x8000

# Write astx data to input
for i, b in enumerate(astx_data):
    emu.writeMemoryValue(toAddr(SEEDCIPHER_INPUT_ADDR + i), 1, b)

# Clear output
for i in range(64):
    emu.writeMemoryValue(toAddr(SEEDCIPHER_OUTPUT_ADDR + i), 1, 0)

# Find seedCipher function (fcn.08106983)
seedCipher = None
for func in func_manager.getFunctions(True):
    if str(func.getEntryPoint()) == "08106983":
        seedCipher = func
        print "   Found seedCipher at", func.getEntryPoint()
        break

if not seedCipher:
    addr = toAddr(0x08106983)
    seedCipher = func_manager.getFunctionAt(addr)
    if seedCipher:
        print "   Found seedCipher at", addr

if seedCipher:
    # Call seedCipher(input_ptr, output_ptr, key_schedule, data_length, iv, mode)
    emu.writeRegister("ESP", STACK_ADDR)
    emu.writeStackValue(0, 4, 0x99999999)              # Return address
    emu.writeStackValue(4, 4, SEEDCIPHER_INPUT_ADDR)   # input_ptr
    emu.writeStackValue(8, 4, SEEDCIPHER_OUTPUT_ADDR)  # output_ptr  
    emu.writeStackValue(12, 4, KEY_SCHEDULE_ADDR)      # key_schedule
    emu.writeStackValue(16, 4, 64)                     # data_length (all 64 bytes)
    emu.writeStackValue(20, 4, IV_ADDR)                # iv
    emu.writeStackValue(24, 4, 0)                      # mode (0 = decrypt)

    print "   Calling seedCipher with 64 bytes of astxcfg.dat..."
    emu.run(seedCipher.getEntryPoint(), None, monitor)
    
    # Check return value
    result = emu.readRegister("EAX")
    print "   seedCipher return value: %d (0x%x)" % (result, result)
    
    # Read output
    print "   seedCipher output (64 bytes):"
    for i in range(0, 64, 16):
        row = []
        for j in range(16):
            if i + j < 64:
                val = emu.readMemoryByte(toAddr(SEEDCIPHER_OUTPUT_ADDR + i + j))
                row.append("%02x" % (val & 0xFF))
        print "     " + " ".join(row)
    
    print "   This is what we need to reproduce in our Python implementation!"
else:
    print "   ERROR: Could not find seedCipher function"

print "\n" + "=" * 60
print "Test complete!"
emu.dispose()
