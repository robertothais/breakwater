#!/usr/bin/env python3
"""
ASTx Debug Log Decryption Tool

Decrypts encrypted debug log files from ASTx surveillance software.
Uses the hardcoded GUID key from initDefaultKey() function discovered through
binary reverse engineering.

Usage: python decrypt_log_file.py <log_file_path>

Key Discovery: Hardcoded GUID {8E3AE284-3C04-c0b8-FC8A-19A78DF238} found in
initDefaultKey() function at 0x0862ea60. Uses AES-CBC with zero IV.
"""

import sys
from pathlib import Path

# Import cryptography library for AES cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES

# Import text quality scoring
from utils import score_plaintext


class ASTxLogDecryptor:
    """Decryptor for ASTx debug log files"""

    def __init__(self):
        # Debug logs use hardcoded GUID from initDefaultKey() as EVP_BytesToKey password
        # Analysis shows OpenSSL EVP cipher API usage, not direct key embedding

        # Raw hex values from initDefaultKey() at 0x0862ea60
        key_data = [
            0x4533387B,  # "{8E3" -> "3E8{"
            0x41453238,  # "82EA" -> "AE28"
            0x34332D33,  # "3-34" -> "43-3"
            0x342D4330,  # "0C-4" -> "4-C0"
            0x2D633062,  # "b0c-" -> "-c0b"
            0x38434638,  # "8FC8" -> "8FC8"
            0x3139412D,  # "-A91" -> "19A-"
            0x41373844,  # "D87A" -> "A78D"
            0x46323833,  # "382F" -> "F238"
            0x7D41,  # "A}" -> "}A" (2 bytes)
        ]

        # Convert to bytes (little-endian) to reconstruct GUID string
        key_bytes = bytearray()
        for i, val in enumerate(key_data):
            if i == len(key_data) - 1:  # Last value is 2 bytes
                key_bytes.extend(val.to_bytes(2, "little"))
            else:  # Others are 4 bytes
                key_bytes.extend(val.to_bytes(4, "little"))

        # Analysis shows debug logs use default password "wiprotecth1"
        # The GUID gets overridden by hardcoded default in configureCipher()
        self.password = "wiprotecth1"

        # Use AES-128-CBC with both derived key and IV from EVP_BytesToKey
        key, iv = self._evp_bytes_to_key()
        self.decryption_key = key
        self.decryption_iv = iv

        print(f"[*] Using hardcoded default password from configureCipher()")
        print(f"[*] Default password: '{self.password}'")
        print(f"[*] Derived AES-128-ECB key: {self.decryption_key.hex()}")
        print(f"[*] ECB mode - no IV needed")

    def _evp_bytes_to_key(self) -> tuple:
        """Derive key and IV using OpenSSL's EVP_BytesToKey algorithm with SHA1"""

        try:
            # Use OpenSSL command to derive key/IV exactly like the binary does
            import subprocess

            result = subprocess.run(
                [
                    "openssl",
                    "enc",
                    "-aes-128-cbc",
                    "-k",
                    self.password,
                    "-P",
                    "-md",
                    "sha1",
                    "-nosalt",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse output: key=...\niv=...
            lines = result.stdout.strip().split("\n")
            key_line = [l for l in lines if l.startswith("key=")][0]
            iv_line = [l for l in lines if l.startswith("iv =")][0]

            key_hex = key_line.split("=")[1]
            iv_hex = iv_line.split("=")[1]

            key = bytes.fromhex(key_hex)
            iv = bytes.fromhex(iv_hex)
            return key, iv

        except Exception as e:
            print(f"[-] OpenSSL command failed: {e}")
            # Fallback to manual EVP_BytesToKey implementation
            import hashlib

            key_len, iv_len = 16, 16
            password = self.password.encode("utf-8")

            d = d_i = b""
            while len(d) < (key_len + iv_len):
                d_i = hashlib.sha1(d_i + password).digest()
                d += d_i

            return d[:key_len], d[key_len : key_len + iv_len]

    def _aes_decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES-128-ECB with EVP_BytesToKey derived key"""
        try:
            cipher = Cipher(
                AES(self.decryption_key),
                modes.ECB(),  # ECB mode - no IV needed!
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(data) + decryptor.finalize()
            return self._remove_padding(decrypted)
        except Exception as e:
            print(f"[-] AES-128-ECB decryption failed: {e}")
            return data

    def _remove_padding(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding from decrypted data"""
        if len(data) == 0:
            return data

        padding_length = data[-1]
        if padding_length > 16 or padding_length == 0:
            return data

        # Verify padding is correct
        for i in range(padding_length):
            if data[-(i + 1)] != padding_length:
                return data

        return data[:-padding_length]

    def decrypt_log_file(self, log_file_path: Path) -> str:
        """
        Decrypt debug log file with format:
        [2-byte size][encrypted data][2-byte size][encrypted data]...
        """

        if not log_file_path.exists():
            print(f"[-] Log file not found: {log_file_path}")
            return ""

        print(f"[*] Decrypting log file: {log_file_path}")
        print(f"[*] File size: {log_file_path.stat().st_size} bytes")

        all_decrypted = ""

        try:
            with open(log_file_path, "rb") as f:
                while True:
                    # Read 2-byte size header (try big-endian)
                    size_header = f.read(2)
                    if len(size_header) != 2:
                        break

                    entry_size = int.from_bytes(size_header, "little")
                    if entry_size == 0 or entry_size > 8192:
                        break

                    # Read encrypted entry data
                    encrypted_data = f.read(entry_size)
                    if len(encrypted_data) != entry_size:
                        break

                    # Decrypt the entry using AES-128-CBC
                    decrypted_data = self._aes_decrypt(encrypted_data)

                    # Add to full decrypted text
                    try:
                        log_entry = decrypted_data.decode("utf-8", errors="replace")
                        all_decrypted += log_entry
                    except:
                        all_decrypted += f"[BINARY:{len(decrypted_data)}]"

        except Exception as e:
            print(f"[-] Error reading log file: {e}")
            return ""

        # Use proper text quality scoring
        if len(all_decrypted) > 0:
            candidate_bytes = all_decrypted.encode("utf-8", errors="ignore")
            score, details, is_text = score_plaintext(candidate_bytes)

            if is_text:
                print(
                    f"[+] Decryption successful - score: {score:.2f}, entropy: {details['entropy_bits_per_byte']:.1f}"
                )
                return all_decrypted
            else:
                print(
                    f"[-] Decryption failed - score: {score:.2f}, printable: {details['printable_ratio']:.1%}, entropy: {details['entropy_bits_per_byte']:.1f}"
                )
                return ""
        else:
            print("[-] No data decrypted")
            return ""

    def save_decrypted_log(self, entries: list, output_path: Path):
        """Save decrypted log entries to text file"""

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write("# ASTx Decrypted Debug Log\n")
                f.write(f"# Total entries: {len(entries)}\n")
                f.write("# " + "=" * 50 + "\n\n")

                for i, entry in enumerate(entries, 1):
                    f.write(f"Entry #{i:03d}:\n")
                    f.write(entry)
                    if not entry.endswith("\n"):
                        f.write("\n")
                    f.write("\n" + "-" * 40 + "\n\n")

            print(f"[+] Saved decrypted log to: {output_path}")

        except Exception as e:
            print(f"[-] Error saving decrypted log: {e}")


def main():
    if len(sys.argv) != 2:
        print("ASTx Debug Log Decryption Tool")
        print()
        print("Usage: python decrypt_log_file.py <log_file_path>")
        print()
        print("Supported log files:")
        print("  - Debug.log")
        print("  - CfgDebug.log")
        print("  - AmbassDebug.log")
        print("  - Any other encrypted debug log files")
        print()
        print("The tool uses the hardcoded GUID key discovered in initDefaultKey()")
        print("and handles the special log format with 2-byte size headers per entry.")
        return 1

    log_file_path = Path(sys.argv[1])

    try:
        decryptor = ASTxLogDecryptor()
        decrypted_text = decryptor.decrypt_log_file(log_file_path)

        if decrypted_text:
            # Print to stdout
            print("\n" + "=" * 50)
            print("DECRYPTED LOG CONTENT:")
            print("=" * 50)
            print(decrypted_text)
            return 0
        else:
            return 1

    except Exception as e:
        print(f"[-] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())


#   writeDebugLog(param_1)
#   │
#   ├─ snprintf(local_420, 0x400, "[%s][%s][t%u][%s] %s\n", ...)
#   │  └─ Creates log message text in local_420 buffer
#   │
#   ├─ encryptBuffer(local_420, sVar7, 0, &local_638)
#      │  ├─ param_1: local_420 (log message text)
#      │  ├─ param_2: sVar7 (message length)
#      │  ├─ param_3: 0 (crypto mode/flags)
#      │  └─ param_4: &local_638 (output length pointer)
#      │
#      └─ createCryptoContext(param_3=0, 0)
#         │  ├─ param_1: 0 (NULL - triggers default key)
#         │  └─ param_2: 0 (crypto mode)
#         │
#         ├─ initDefaultKey() [CALLED because param_1 == NULL]
#         │  └─ Sets DAT_0862ea60 = GUID bytes {83E82EA3-340C-4b0c-8FC8-A91D87A382FA}
#         │
#         ├─ local_14 = &DAT_0862ea60 (GUID string)
#         │
#         └─ storeKeyInContext(context, local_14=GUID_string, param_2=0)
#            │
#            └─ configureCipher(context, param_2=0)
#               │
#               ├─ if (param_2 == 0): [TRUE - our path]
#               │  │
#               │  ├─ Sets default password: "wiprotech1" (10 chars)
#               │  │  └─ Overwrites the GUID with hardcoded default!
#               │  │
#               │  ├─ EVP_BytesToKey(
#               │  │     cipher=FUN_082388d0(),     // AES-128-CBC
#               │  │     hash=FUN_082479d0(),       // MD5? (need to verify)
#               │  │     salt=0,                   // No salt
#               │  │     password="wiprotech1",    // 10 bytes
#               │  │     password_len=10,
#               │  │     iterations=1,             // param_1[2]
#               │  │     key_out=local_40,         // 16 bytes
#               │  │     iv_out=local_30           // 16 bytes
#               │  │  )
#               │  │
#               │  └─ EVP_CipherInit_ex(context, AES-128-CBC, NULL, key, iv)
#               │
#               └─ Returns configured crypto context


# FASCINATING! The pattern is even more revealing than I thought:

#   🔍 Visual Pattern Analysis

#   Block-Level Repetition:

#   - Block 1: 3802434da6d9a306ba16ba9c4ae15da3 - IDENTICAL across ALL entries
#   - Block 2: Two variants:
#     - 2d2302c1f49136f8672e942d69fb88c7 (Entries 1-6)
#     - 97cbe367eafcebf6b1f85b85a5dd0e98 (Entries 7-10)

#   This Pattern Screams ECB Mode!

#   In ECB mode:
#   - Same plaintext block → same ciphertext block
#   - Block 1 is identical = first 16 bytes of log message are identical
#   - Block 2 has 2 variants = second 16 bytes have 2 different patterns

#   This is impossible in CBC mode unless:
#   - All entries use the same IV (breaks security)
#   - There's a bug in the implementation

#   Log Message Structure Theory:

#   [FIXED_HEADER_16_BYTES][TIMESTAMP_OR_THREAD_16_BYTES][VARIABLE_MESSAGE...]
#         ↓                           ↓                         ↓
#     Always same          Two different patterns      Different per entry
#   (Block 1 identical)    (Block 2 has variants)     (Block 3+ varies)

#   This is definitive proof we need to test AES-128-ECB mode!
