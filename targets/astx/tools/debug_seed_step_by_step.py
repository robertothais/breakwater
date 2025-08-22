#!/usr/bin/env python2
# Step-by-step debugging to find discrepancy between Python and binary

import struct
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor

print "=" * 80
print "STEP-BY-STEP SEED DEBUGGING"
print "=" * 80

# Create emulator and monitor
emu = EmulatorHelper(currentProgram)
monitor = ConsoleTaskMonitor()

# Allocate memory regions
STACK_ADDR = 0x10000
KEY_ADDR = 0x2000
KEY_SCHEDULE_ADDR = 0x3000
DATA_ADDR = 0x4000
OUTPUT_ADDR = 0x5000
IV_ADDR = 0x6000

# Set up stack
emu.writeRegister("ESP", STACK_ADDR)

# Get function manager
func_manager = currentProgram.getFunctionManager()

print "\nSTEP 1: KEY EXPANSION COMPARISON"
print "-" * 50

# Set up AhnlabSecretKey
ahnlab_key = [0x41, 0x68, 0x6E, 0x6C, 0x61, 0x62, 0x53, 0x65,
              0x63, 0x72, 0x65, 0x74, 0x4B, 0x65, 0x79, 0x00]

print "Input key: " + "".join("%02x" % b for b in ahnlab_key)

# Write key to memory
for i, b in enumerate(ahnlab_key):
    emu.writeMemoryValue(toAddr(KEY_ADDR + i), 1, b)

# Find and call seedKeyExpand
seedKeyExpand = None
for func in func_manager.getFunctions(True):
    if "seedKeyExpand" in func.getName() or str(func.getEntryPoint()) == "08105c2d":
        seedKeyExpand = func
        break

if not seedKeyExpand:
    seedKeyExpand = func_manager.getFunctionAt(toAddr(0x08105c2d))

# Call seedKeyExpand
emu.writeRegister("ESP", STACK_ADDR)
emu.writeStackValue(0, 4, 0x99999999)        # Return address
emu.writeStackValue(4, 4, KEY_SCHEDULE_ADDR) # Output buffer
emu.writeStackValue(8, 4, 16)                # Key length  
emu.writeStackValue(12, 4, KEY_ADDR)         # Key data

entry = seedKeyExpand.getEntryPoint() if seedKeyExpand else toAddr(0x08105c2d)
emu.run(entry, None, monitor)

# Read binary key schedule
print "\nBinary key schedule (first 64 bytes):"
binary_key_schedule = []
for i in range(112):  # Full key schedule is 112 bytes
    val = emu.readMemoryByte(toAddr(KEY_SCHEDULE_ADDR + i))
    binary_key_schedule.append(val & 0xFF)

# Display first 64 bytes for comparison
for i in range(0, 64, 16):
    row = []
    for j in range(16):
        if i + j < 64:
            row.append("%02x" % binary_key_schedule[i + j])
    print "  " + " ".join(row)

# Python key schedule for comparison
print "\nPython key schedule (from custom_seed.py - first 64 bytes):"
print "def ahnlab_key_expand(key):"
print "    # This should match the binary output above"
print "    # If it doesn't, we found our first discrepancy!"

print "\nSTEP 2: SINGLE BLOCK DECRYPTION COMPARISON"  
print "-" * 50

# Test with first block of astxcfg.dat
test_block = [0x62, 0xc8, 0x60, 0x80, 0x2d, 0x83, 0x93, 0xc5, 
              0x5e, 0xd5, 0xfe, 0xa4, 0x2b, 0x01, 0x07, 0xf3]

print "Input block: " + "".join("%02x" % b for b in test_block)

# Write test block to memory
for i, b in enumerate(test_block):
    emu.writeMemoryValue(toAddr(DATA_ADDR + i), 1, b)

# Find and call seedDecrypt (single block)
seedDecrypt = None
for func in func_manager.getFunctions(True):
    if "seedDecrypt" in func.getName() or str(func.getEntryPoint()) == "08104f66":
        seedDecrypt = func
        break

if not seedDecrypt:
    seedDecrypt = func_manager.getFunctionAt(toAddr(0x08104f66))

# Call seedDecrypt on single block
emu.writeRegister("ESP", STACK_ADDR)
emu.writeStackValue(0, 4, 0x99999999)         # Return address
emu.writeStackValue(4, 4, DATA_ADDR)          # Data to decrypt (in/out)
emu.writeStackValue(8, 4, KEY_SCHEDULE_ADDR)  # Key schedule

entry = seedDecrypt.getEntryPoint() if seedDecrypt else toAddr(0x08104f66)
emu.run(entry, None, monitor)

# Read decrypted block (before CBC XOR)
print "\nBinary raw block decrypt (before CBC XOR):"
raw_decrypt = []
for i in range(16):
    val = emu.readMemoryByte(toAddr(DATA_ADDR + i))
    raw_decrypt.append(val & 0xFF)
print "  " + "".join("%02x" % b for b in raw_decrypt)

print "\nPython raw block decrypt (from custom_seed.py):"
print "def ahnlab_seed_decrypt_block(block, key_schedule):"
print "    # This should match the binary output above"
print "    # Input:  62c860802d8393c55ed5fea42b0107f3"
print "    # Output: [expected binary result]"

print "\nSTEP 3: IV VERIFICATION"
print "-" * 50

# Set up IV exactly as binary does
iv_bytes = [0x01, 0x02, 0x03, 0x04] + [0x00] * 12
print "IV used by binary: " + "".join("%02x" % b for b in iv_bytes)

for i, b in enumerate(iv_bytes):
    emu.writeMemoryValue(toAddr(IV_ADDR + i), 1, b)

print "\nPython IV (from custom_seed.py):"
print "IV = bytes([1, 2, 3, 4] + [0] * 12)"
print "Should match: 01020304000000000000000000000000"

print "\nSTEP 4: CBC FIRST BLOCK TEST"
print "-" * 50

# Reset test block for CBC test
for i, b in enumerate(test_block):
    emu.writeMemoryValue(toAddr(DATA_ADDR + i), 1, b)

# Manually do CBC: decrypt then XOR with IV
print "Manual CBC calculation:"
print "1. Raw decrypt: " + "".join("%02x" % b for b in raw_decrypt)
print "2. XOR with IV: " + "".join("%02x" % b for b in iv_bytes[:16])

# Calculate CBC result manually
cbc_result = []
for i in range(16):
    cbc_byte = raw_decrypt[i] ^ iv_bytes[i]
    cbc_result.append(cbc_byte)

print "3. CBC result:  " + "".join("%02x" % b for b in cbc_result)

print "\nPython CBC (from custom_seed.py first block):"
print "Should match the CBC result above"

print "\nSTEP 5: FULL CBC USING seedCipher"
print "-" * 50

# Test seedCipher on just first block to verify CBC implementation
print "Calling seedCipher on first block only..."

# Clear output
for i in range(16):
    emu.writeMemoryValue(toAddr(OUTPUT_ADDR + i), 1, 0)

# Reset input block
for i, b in enumerate(test_block):
    emu.writeMemoryValue(toAddr(DATA_ADDR + i), 1, b)

# Find seedCipher
seedCipher = None
for func in func_manager.getFunctions(True):
    if str(func.getEntryPoint()) == "08106983":
        seedCipher = func
        break

if not seedCipher:
    seedCipher = func_manager.getFunctionAt(toAddr(0x08106983))

# Call seedCipher on single block
emu.writeRegister("ESP", STACK_ADDR)
emu.writeStackValue(0, 4, 0x99999999)         # Return address
emu.writeStackValue(4, 4, DATA_ADDR)          # input_ptr
emu.writeStackValue(8, 4, OUTPUT_ADDR)        # output_ptr  
emu.writeStackValue(12, 4, KEY_SCHEDULE_ADDR) # key_schedule
emu.writeStackValue(16, 4, 16)                # data_length (single block)
emu.writeStackValue(20, 4, IV_ADDR)           # iv
emu.writeStackValue(24, 4, 0)                 # mode (0 = decrypt)

entry = seedCipher.getEntryPoint() if seedCipher else toAddr(0x08106983)
emu.run(entry, None, monitor)

# Read seedCipher output
print "\nseedCipher output (first block only):"
seedcipher_output = []
for i in range(16):
    val = emu.readMemoryByte(toAddr(OUTPUT_ADDR + i))
    seedcipher_output.append(val & 0xFF)
print "  " + "".join("%02x" % b for b in seedcipher_output)

print "\nCOMPARISON SUMMARY:"
print "=" * 50
print "If manual CBC result matches seedCipher output: CBC logic is correct"
print "If they differ: There's something else in seedCipher we're missing"
print "If binary raw decrypt differs from Python: Block decrypt is wrong"
print "If binary key schedule differs from Python: Key expansion is wrong"

print "\n" + "=" * 80
print "Debug complete! Check each step above to find the discrepancy."
emu.dispose()