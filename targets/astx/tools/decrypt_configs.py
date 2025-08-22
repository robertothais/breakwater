#!/usr/bin/env python3
"""
ASTx Master Configuration Decryption Tool

Decrypts all AhnLab Safe Transaction configuration files:
1. AppConfig files (local)
2. Downloads and decrypts remote policy/version files
3. Decrypts local starter policy files
4. Recovers RSA keys in appconfig

All files use AES CBC with "firewallkeyseed1" key + zero IV.
"""

import base64
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Import cryptography library for AES cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES


class ASTxConfigDecryptor:
    """Master decryptor for all ASTx configuration files"""

    def __init__(self):
        # Base key string from generateAESKeyFromXorString
        self.base_key = "KEY2ENCRYPT&DECRYPT"

        # XOR numbers from getAuthContent (DAT_0862e480)
        # Re-examining hex values more carefully (little-endian):
        # 0x343a3534 = bytes 34,35,3a,34 = "45:4"
        hex_values = [
            0x343A3534,
            0x33343A34,
            0x3A37383A,
            0x343A3035,
            0x37343A37,
            0x3A32363A,
            0x353A3035,
            0x35343A33,
            0x3A35383A,
            0x333A3333,
            0x39333A32,
            0x3A39393A,
        ]

        # Convert hex to ASCII bytes and build string
        ascii_chars = []
        for hex_val in hex_values:
            # Convert 32-bit int to 4 bytes (little-endian)
            bytes_le = hex_val.to_bytes(4, byteorder="little")
            ascii_chars.extend(bytes_le.decode("ascii", errors="ignore"))

        self.xor_string = "".join(ascii_chars).rstrip("\x00")
        print(f"Reconstructed XOR string: '{self.xor_string}'", file=sys.stderr)

        # Generate the actual decryption key
        self.decryption_key = self._generate_key()

        # IV from previous analysis
        self.iv = bytes([1, 2, 3, 4] + [0] * 12)  # 16 bytes

        print(f"Base key: {self.base_key}")
        print(f"XOR string: {self.xor_string}")
        print(f"Generated AES key: {self.decryption_key.hex()}")
        print(f"Discovered IV (from binary): {self.iv.hex()}")
        print(f"Actually using IV: {'00' * 16} (zero IV - this is what works!)")
        print()

    def _generate_key(self) -> bytes:
        """
        Generate AES decryption key using the XOR method from FUN_08059915

        Algorithm:
        1. Parse numbers from the XOR string (format: "num:num:num:...")
        2. XOR each byte of base_key with corresponding parsed number
        3. Return as 16-byte key (truncate or pad as needed)
        """
        # Parse numbers using the exact algorithm from FUN_08059915
        # Algorithm: extract consecutive digit sequences, ignore non-digits
        numbers = []
        current_number = ""

        for char in self.xor_string:
            if char.isdigit():
                current_number += char
            else:
                # Non-digit character, finish current number if any
                if current_number:
                    numbers.append(int(current_number))
                    current_number = ""

        # Don't forget the last number if string doesn't end with non-digit
        if current_number:
            numbers.append(int(current_number))

        print(f"Parsed numbers: {numbers}", file=sys.stderr)

        # Generate key by XORing base_key with numbers
        key_bytes = []
        for i in range(len(self.base_key)):
            base_byte = ord(self.base_key[i])
            if i < len(numbers):
                # Use modulo 256 to keep values in byte range (0-255)
                xor_number = numbers[i] % 256
                xor_byte = base_byte ^ xor_number
                key_bytes.append(xor_byte)
                print(
                    f"  byte[{i}]: '{self.base_key[i]}' ({base_byte}) ^ {numbers[i]}%256={xor_number} = {xor_byte}",
                    file=sys.stderr,
                )
            else:
                # No more numbers, use base key as-is
                key_bytes.append(base_byte)
                print(
                    f"  byte[{i}]: '{self.base_key[i]}' ({base_byte}) (no XOR)",
                    file=sys.stderr,
                )

        # Convert to 16-byte key for AES
        key_data = bytes(key_bytes)
        print(
            f"Key before truncation: length={len(key_data)}, hex={key_data.hex()}",
            file=sys.stderr,
        )
        print(
            f"Key as ASCII: {key_data[:16].decode('ascii', errors='ignore')}",
            file=sys.stderr,
        )

        if len(key_data) > 16:
            key_data = key_data[:16]  # Truncate to 16 bytes
            print(f"Truncated to 16 bytes: {key_data.hex()}", file=sys.stderr)
        elif len(key_data) < 16:
            key_data = key_data.ljust(16, b"\x00")  # Pad with zeros
            print(f"Padded to 16 bytes: {key_data.hex()}", file=sys.stderr)

        return key_data

    def _aes_decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES CBC with zero IV"""
        try:
            zero_iv = b"\x00" * 16
            cipher = Cipher(
                AES(self.decryption_key), modes.CBC(zero_iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(data) + decryptor.finalize()
            return self._remove_padding(decrypted)
        except Exception as e:
            print(f"  AES CBC decryption failed: {e}", file=sys.stderr)
            return data

    def _remove_padding(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding from decrypted data"""
        if len(data) == 0:
            return data

        padding_length = data[-1]
        if padding_length > 16 or padding_length == 0:
            return data

        # Check if all padding bytes are correct
        for i in range(padding_length):
            if data[-(i + 1)] != padding_length:
                return data

        return data[:-padding_length]

    def _save_decrypted_file(self, content: bytes, filename: str) -> Path:
        """Save decrypted content to analysis/decrypted/ directory"""

        output_dir = Path("analysis/decrypted")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / filename

        try:
            # Try to save as text if it's valid ASCII/UTF-8
            text = content.decode("utf-8")
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"[+] Saved decrypted text file: {output_file}")
        except UnicodeDecodeError:
            # Save as binary if text decoding fails
            with open(output_file, "wb") as f:
                f.write(content)
            print(f"[+] Saved decrypted binary file: {output_file}")

        return output_file

    def decrypt_file(self, file_path: Path, output_name: str | None = None) -> bool:
        """Decrypt a single file (Base64 → AES decrypt → save)"""

        if not file_path.exists():
            print(f"[-] File not found: {file_path}")
            return False

        print(f"[*] Decrypting: {file_path}")

        try:
            # Read encrypted file
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            print(f"    [*] Input file size: {len(encrypted_data)} bytes")

            # Step 1: Base64 decode
            print("    [*] Step 1: Base64 decoding...")
            try:
                base64_decoded = base64.b64decode(encrypted_data)
                print(f"    [*] Base64 decoded size: {len(base64_decoded)} bytes")
            except Exception as e:
                print(f"    [-] Base64 decode failed: {e}")
                return False

            # Step 2: AES decrypt
            print("    [*] Step 2: AES decryption...")
            print("    [*] Using AES CBC with zero IV (proven working method)")
            decrypted_data = self._aes_decrypt(base64_decoded)

            # Step 3: Save result
            if output_name is None:
                output_name = file_path.name

            self._save_decrypted_file(decrypted_data, output_name)
            return True

        except Exception as e:
            print(f"    [-] Error decrypting {file_path}: {e}")
            return False

    def download_and_decrypt(self, url: str, output_name: str) -> bool:
        """Download encrypted file from URL and decrypt it"""

        print(f"[*] Downloading: {url}")

        try:
            with urllib.request.urlopen(url) as response:
                encrypted_data = response.read()

            print(f"    [+] Downloaded {len(encrypted_data)} bytes")

            # Step 1: Base64 decode
            print("    [*] Step 1: Base64 decoding...")
            try:
                base64_decoded = base64.b64decode(encrypted_data)
                print(f"    [*] Base64 decoded size: {len(base64_decoded)} bytes")
            except Exception as e:
                print(f"    [-] Base64 decode failed: {e}")
                return False

            # Step 2: AES decrypt
            print("    [*] Step 2: AES decryption...")
            print("    [*] Using AES CBC with zero IV (proven working method)")
            decrypted_data = self._aes_decrypt(base64_decoded)

            # Step 3: Save result
            self._save_decrypted_file(decrypted_data, output_name)
            return True

        except urllib.error.URLError as e:
            print(f"    [-] Download failed: {e}")
            return False
        except Exception as e:
            print(f"    [-] Error downloading/decrypting {url}: {e}")
            return False

    def extract_urls_from_appconfig(self, appconfig_file: Path) -> tuple:
        """Extract URLs from decrypted AppConfig file"""

        if not appconfig_file.exists():
            return None, None

        try:
            with open(appconfig_file, encoding="utf-8") as f:
                content = f.read()

            starter_url = None
            version_url = None

            for line in content.split("\n"):
                if line.startswith("StarterPolicyURL="):
                    starter_url = line.split("=", 1)[1].strip()
                elif line.startswith("VersionURL="):
                    version_url = line.split("=", 1)[1].strip()

            return starter_url, version_url

        except Exception as e:
            print(f"    [-] Error extracting URLs from AppConfig: {e}")
            return None, None

    def run_full_decryption(self):
        """Run complete decryption of all ASTx configuration files"""

        print("[!] ASTx Master Configuration Decryptor v1.0")
        print("=" * 55)

        success_count = 0
        total_count = 0

        # 1. Decrypt local AppConfig file
        print("\n[>] Phase 1: Local AppConfig Files")
        appconfig_path = Path(
            "unpacked/rootfs/opt/AhnLab/ASTx/ConfigFile/appconfig.xml"
        )
        if self.decrypt_file(appconfig_path, "appconfig.xml"):
            success_count += 1
        total_count += 1

        # 2. Extract URLs from decrypted AppConfig and download remote files
        print("\n[>] Phase 2: Remote Files (from AppConfig URLs)")
        decrypted_appconfig = Path("analysis/decrypted/appconfig.xml")

        if decrypted_appconfig.exists():
            starter_url, version_url = self.extract_urls_from_appconfig(
                decrypted_appconfig
            )

            if starter_url:
                if self.download_and_decrypt(
                    starter_url, "starter_ply_linux.downloaded.plist"
                ):
                    success_count += 1
                total_count += 1

            if version_url:
                if self.download_and_decrypt(
                    version_url, "astx_ver_linux.downloaded.ini"
                ):
                    success_count += 1
                total_count += 1
        else:
            print("    [!] AppConfig not decrypted, skipping remote downloads")
            total_count += 2

        # 3. Decrypt local starter policy file
        print("\n[>] Phase 3: Local Policy Files")
        local_starter = Path(
            "unpacked/rootfs/opt/AhnLab/ASTx/ConfigFile/starter_ply_linux.html"
        )
        if self.decrypt_file(local_starter, "starter_ply_linux.plist"):
            success_count += 1
        total_count += 1

        # Note: Skipping other config files (config.xml, suarez.conf.client)
        # as they may use different encryption methods

        # Summary
        print("\n" + "=" * 55)
        print(f"[+] Decryption Complete: {success_count}/{total_count} files processed")

        if success_count > 0:
            print("[+] Decrypted files saved to: analysis/decrypted/")

        return success_count == total_count

    def decode_obfuscated_rsa_keys(self):
        """Decode obfuscated RSA keys - simplified to current knowledge"""
        print("\n[>] RSA Key Decoding")

        appconfig_path = Path("analysis/decrypted/appconfig.xml")
        if not appconfig_path.exists():
            print("[-] AppConfig not found")
            return False

        with open(appconfig_path) as f:
            content = f.read()

        # Extract keys
        public_key = None
        private_key = None

        in_rsa_section = False
        for line in content.split("\n"):
            line = line.strip()
            if line == "[SECTION_S2C_RSA_KEY]":
                in_rsa_section = True
            elif line.startswith("[") and in_rsa_section:
                break
            elif in_rsa_section:
                if line.startswith("PublicKey="):
                    public_key = line.split("=", 1)[1]
                elif line.startswith("PrivateKey="):
                    private_key = line.split("=", 1)[1]

        if not public_key or not private_key:
            print("[-] Keys not found")
            return False

        print(f"[*] PublicKey: {len(public_key)} chars")
        print(f"[*] PrivateKey: {len(private_key)} chars")

        # Decode
        decoded_public = self._decode_rsa_key(public_key, "PublicKey")
        decoded_private = self._decode_rsa_key(private_key, "PrivateKey")

        # Only save valid PEM
        success = 0
        public_key_path = Path("analysis/decrypted/public_key.pem")
        private_key_path = Path("analysis/decrypted/private_key.pem")

        if decoded_public and decoded_public.startswith("-----BEGIN"):
            with open(public_key_path, "w") as f:
                f.write(decoded_public)
            print("[+] Saved public key")
            success += 1

        if decoded_private and decoded_private.startswith("-----BEGIN"):
            with open(private_key_path, "w") as f:
                f.write(decoded_private)
            print("[+] Saved private key")
            success += 1

        # Verify the keys match by comparing modulus
        if success == 2:
            if self._verify_key_pair(public_key_path, private_key_path):
                print("[+] Key pair verified - modulus values match!")
            else:
                print("[-] WARNING: Key pair modulus mismatch!")
                success = 0

        return success == 2

    def _decode_rsa_key(self, encoded_key: str, key_type: str):
        """Decode RSA key using the fully reverse-engineered algorithm"""
        print(f"Decoding {key_type}...")

        # Step 1: Filter every 5th character and XOR with 4
        filtered = ""
        for i, char in enumerate(encoded_key):
            if i % 5 != 0:  # Skip positions 0,5,10,15...
                filtered += chr(ord(char) ^ 4)
        print(f"  After filter/XOR: {len(filtered)} chars")

        # Step 2: Generate custom alphabet using param2=4 (hardcoded for RSA)
        alphabet = self._derive_custom_base64_alphabet(salt=4)
        print(f"  Custom alphabet: {alphabet}")

        # Step 3: Custom base64 decode
        decoded = self._custom_base64_decode(filtered, alphabet)
        if not decoded:
            print("  Decode failed")
            return None

        print(f"  Decoded: {len(decoded)} bytes")

        # Check as text
        try:
            text = decoded.decode("utf-8", errors="strict")

            # Return only if valid PEM
            if text.startswith("-----BEGIN"):
                print(f"  [+] Successfully decoded {key_type}")
                return text
            else:
                print("  Not valid PEM format")
                return None
        except Exception as e:
            print(f"  Decode error: {e}")
            return None

    def _derive_custom_base64_alphabet(self, salt: int) -> str:
        """Derive custom base64 alphabet from hardcoded seed material"""

        # Actual seed from memory dump at 0x08422b20
        # -f3_v8spVG29kzl5XuDNLci6rdoQy0ZFqmSACMgYbjRe7nPTOEKtawUhJ4HWIxB1
        seed_str = "-f3_v8spVG29kzl5XuDNLci6rdoQy0ZFqmSACMgYbjRe7nPTOEKtawUhJ4HWIxB1"
        seed_bytes = seed_str.encode("ascii")

        # Implementation matching Ghidra decompilation of deriveCustomBase64Alphabet
        if salt < 1:
            step = 0x40  # 64
        else:
            step = salt % 0x40 + 1  # salt=4 gives step=5

        # Generate alphabet with the discovered algorithm
        alphabet = []
        k = 0  # outer counter

        while len(alphabet) < 64:
            for j in range(step - 1, -1, -1):  # j from step-1 down to 0
                idx = j + step * k
                if idx < 64 and idx < len(seed_bytes):
                    alphabet.append(chr(seed_bytes[idx]))
                    if len(alphabet) >= 64:
                        break
            k += 1

        result = "".join(alphabet)
        return result

    def _custom_base64_decode(self, data: str, alphabet: str):
        """Decode data using custom base64 alphabet - matches binary logic"""

        try:
            # Create mapping from custom alphabet to indices
            char_to_value = {}
            for i, char in enumerate(alphabet):
                char_to_value[char] = i

            # Padding is '*' not '=' (from RE analysis)
            padding_char = "*"

            decoded = bytearray()
            char_count = 0
            output_pos = 0

            for char in data:
                # Handle space -> '+' conversion (from binary analysis)
                if char == " ":
                    char = "+"

                # Check for padding or end
                if char == "\0" or char == padding_char:
                    break

                # Look up character in alphabet
                if char in char_to_value:
                    value = char_to_value[char]

                    # Standard base64 decoding math (matches binary logic)
                    pos_in_quartet = char_count % 4

                    if pos_in_quartet == 0:
                        # First char - store in temp (6 bits, shift left 2)
                        if output_pos >= len(decoded):
                            decoded.append(0)
                        decoded[output_pos] = (value << 2) & 0xFF

                    elif pos_in_quartet == 1:
                        # Second char - complete first byte, start second
                        decoded[output_pos] |= (value >> 4) & 0x3F
                        output_pos += 1
                        if output_pos >= len(decoded):
                            decoded.append(0)
                        decoded[output_pos] = (value << 4) & 0xFF

                    elif pos_in_quartet == 2:
                        # Third char - complete second byte, start third
                        decoded[output_pos] |= (value >> 2) & 0x3F
                        output_pos += 1
                        if output_pos >= len(decoded):
                            decoded.append(0)
                        decoded[output_pos] = (value << 6) & 0xFF

                    elif pos_in_quartet == 3:
                        # Fourth char - complete third byte
                        decoded[output_pos] |= value & 0x3F
                        output_pos += 1

                    char_count += 1

            # Trim to actual output length
            return bytes(decoded[:output_pos])

        except Exception as e:
            print(f"        [-] Custom base64 decode error: {e}")
            return None

    def _verify_key_pair(self, public_key_path: Path, private_key_path: Path) -> bool:
        """Verify that public and private keys form a matching pair by comparing
        modulus"""
        try:
            # Extract modulus from public key
            result = subprocess.run(
                [
                    "openssl",
                    "rsa",
                    "-pubin",
                    "-in",
                    str(public_key_path),
                    "-modulus",
                    "-noout",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            public_modulus = result.stdout.strip()

            # Extract modulus from private key
            result = subprocess.run(
                ["openssl", "rsa", "-in", str(private_key_path), "-modulus", "-noout"],
                capture_output=True,
                text=True,
                check=True,
            )
            private_modulus = result.stdout.strip()

            # Compare modulus values
            if public_modulus == private_modulus:
                print(f"    Modulus: {public_modulus[:50]}...")
                return True
            else:
                print(f"    Public modulus:  {public_modulus[:50]}...")
                print(f"    Private modulus: {private_modulus[:50]}...")
                return False

        except subprocess.CalledProcessError as e:
            print(f"    [-] Error verifying keys with openssl: {e}")
            return False
        except Exception as e:
            print(f"    [-] Unexpected error during verification: {e}")
            return False


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print("ASTx Master Configuration Decryptor")
        print("")
        print("Usage: python decrypt_configs.py [--rsa-only]")
        print("")
        print("This tool automatically:")
        print("  1. Decrypts local AppConfig files")
        print("  2. Downloads and decrypts remote policy/version files")
        print("  3. Decrypts local starter policy files")
        print("  4. Decodes obfuscated RSA keys")
        print("")
        print("Options:")
        print("  --rsa-only    Only decode RSA keys (skip config decryption)")
        print("")
        print("All decrypted files are saved to analysis/decrypted/")
        print("")
        print("Decryption method: AES CBC + 'firewallkeyseed1' key + zero IV")
        print("RSA decoding: Custom base64 + XOR + character filtering")
        return 0

    try:
        decryptor = ASTxConfigDecryptor()

        # Check for RSA-only mode
        rsa_only = len(sys.argv) > 1 and sys.argv[1] == "--rsa-only"

        if rsa_only:
            print("[!] RSA Key Decoder Mode")
            print("=" * 30)
            success = decryptor.decode_obfuscated_rsa_keys()
        else:
            success = decryptor.run_full_decryption()

            # After full decryption, attempt RSA key decoding
            if success:
                decryptor.decode_obfuscated_rsa_keys()

        return 0 if success else 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
