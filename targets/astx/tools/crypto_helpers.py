#!/usr/bin/env python3
import base64
import hashlib
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Literal

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers.algorithms import SEED
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DecryptResult = tuple[Literal[True], bytes] | tuple[Literal[False], None]


class KeyDerivationMode(str, Enum):
    XOR = "xor"  # XOR with "KEY2ENCRYPT&DECRYPT"
    EVP = "evp"  # OpenSSL EVP_BytesToKey with "wiprotech1"
    STATIC = "static"  # Static GUID key from initDefaultKey


class CipherMode(str, Enum):
    AES_CBC = "aes_cbc"
    SEED_CBC = "seed_cbc"


class DataFormat(str, Enum):
    RAW = "raw"  # Use data as-is
    BASE64 = "base64"  # Base64 decode first
    CHUNKED = "chunked"  # Log file format: 2-byte length + encrypted chunk


# ============================================================================
# KEY DERIVATION FUNCTIONS
# ============================================================================


def derive_xor_key() -> bytes:
    """
    Generate key using XOR method from generateAESKeyFromXorString
    Algorithm: XOR "KEY2ENCRYPT&DECRYPT" with parsed numbers
    """
    # Base key string from generateAESKeyFromXorString
    base_key = "KEY2ENCRYPT&DECRYPT"

    # XOR numbers from getAuthContent (DAT_0862e480)
    # Re-examining hex values more carefully (little-endian):
    # 0x343a3534 = bytes 34,35,3a,34 = "45:4"
    # Let me build this correctly from the hex data
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

    xor_string = "".join(ascii_chars).rstrip("\x00")
    print(f"Reconstructed XOR string: '{xor_string}'", file=sys.stderr)

    # Parse numbers using the exact algorithm from FUN_08059915
    # Algorithm: extract consecutive digit sequences, ignore non-digits
    numbers = []
    current_number = ""

    for char in xor_string:
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
    for i in range(len(base_key)):
        base_byte = ord(base_key[i])
        if i < len(numbers):
            # Use modulo 256 to keep values in byte range (0-255)
            xor_number = numbers[i] % 256
            xor_byte = base_byte ^ xor_number
            key_bytes.append(xor_byte)
            print(
                f"  byte[{i}]: '{base_key[i]}' ({base_byte}) ^ {numbers[i]}%256={xor_number} = {xor_byte}",
                file=sys.stderr,
            )
        else:
            # No more numbers, use base key as-is
            key_bytes.append(base_byte)
            print(
                f"  byte[{i}]: '{base_key[i]}' ({base_byte}) (no XOR)",
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


def derive_evp_key() -> tuple[bytes, bytes]:
    """
    Generate key/IV using OpenSSL EVP_BytesToKey method
    Algorithm: SHA1-based key derivation with "wprotect1" passphrase
    """

    def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
        print("    [DEBUG] EVP_BytesToKey input:", file=sys.stderr)
        print(f"      Password: {password!r} (len={len(password)})", file=sys.stderr)
        print(f"      Salt: {salt.hex()} (len={len(salt)})", file=sys.stderr)
        print(f"      Key length: {key_len}, IV length: {iv_len}", file=sys.stderr)

        m = []
        i = 0
        while len(b"".join(m)) < (key_len + iv_len):
            md_input = m[i - 1] if i > 0 else b""
            md_input += password + salt
            hash_result = hashlib.sha1(md_input).digest()
            m.append(hash_result)
            print(
                f"      Round {i}: input={md_input.hex()[:32]}... -> hash={hash_result.hex()}",
                file=sys.stderr,
            )
            i += 1
        ms = b"".join(m)
        derived_key = ms[:key_len]
        derived_iv = ms[key_len : key_len + iv_len]
        print("    [DEBUG] EVP_BytesToKey output:", file=sys.stderr)
        print(f"      Derived key: {derived_key.hex()}", file=sys.stderr)
        print(f"      Derived IV: {derived_iv.hex()}", file=sys.stderr)
        return derived_key, derived_iv

    passphrase = b"wiprotech1"
    salt = b"\x00" * 8  # 8 zero bytes
    key, _ = evp_bytes_to_key(passphrase, salt, 16, 16)  # AES-128 key + ignore IV
    iv = b"\x00" * 16  # Always use zero IV (matches memset in configureCipher)
    print("    [DEBUG] Final key/IV used for decryption:", file=sys.stderr)
    print(f"      Key: {key.hex()}", file=sys.stderr)
    print(f"      IV:  {iv.hex()}", file=sys.stderr)
    return key, iv


def derive_static_guid_key() -> tuple[bytes, bytes]:
    """
    Use static GUID from initDefaultKey as EVP password
    GUID: {83E82EA3-340C-4b0c-8FC8-A91D87A382FA}
    Processed through EVP_BytesToKey like configureCipher does for NULL keys
    """
    # Reuse the existing EVP function with GUID as password
    guid_password = b"{83E82EA3-340C-4b0c-8FC8-A91D87A382FA}"

    # Use same EVP processing as derive_evp_key but with different password
    def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
        print("    [DEBUG] EVP_BytesToKey for static GUID:", file=sys.stderr)
        print(f"      Password: {password!r} (len={len(password)})", file=sys.stderr)

        m = []
        i = 0
        while len(b"".join(m)) < (key_len + iv_len):
            md_input = m[i - 1] if i > 0 else b""
            md_input += password + salt
            hash_result = hashlib.sha1(md_input).digest()
            m.append(hash_result)
            i += 1
        ms = b"".join(m)
        return ms[:key_len], ms[key_len : key_len + iv_len]

    salt = b"\x00" * 8  # 8 zero bytes
    key, _ = evp_bytes_to_key(guid_password, salt, 16, 16)  # Ignore derived IV
    iv = b"\x00" * 16  # Always use zero IV

    print(f"    [DEBUG] Final static key: {key.hex()}", file=sys.stderr)
    print(f"    [DEBUG] Final static IV: {iv.hex()}", file=sys.stderr)

    return key, iv


def derive_seed_static_key() -> bytes:
    """Generate SEED cipher key from hardcoded string"""
    key = b"AhnlabSecretKey"  # 15 bytes as in binary
    return key + b"\x00"  # Pad to 16 bytes as seedKeySchedule does


def derive_seed_static_iv() -> bytes:
    """Generate SEED cipher IV from binary analysis"""
    return bytes([1, 2, 3, 4] + [0] * 12)  # 16 bytes


# ============================================================================
# DATA PREPROCESSING FUNCTIONS
# ============================================================================


def preprocess_base64_decode(data: bytes) -> bytes:
    try:
        decoded = base64.b64decode(data)
        print(
            f"    [*] Base64 decoded: {len(data)} -> {len(decoded)} bytes",
            file=sys.stderr,
        )
        return decoded
    except Exception as e:
        print(f"    [-] Base64 decode failed: {e}", file=sys.stderr)
        raise


def preprocess_raw(data: bytes) -> bytes:
    """Use data as-is (for config.xml, local files)"""
    return data


def preprocess_chunked(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Parse chunked log file format: 2-byte length + encrypted chunk (repeat)
    Decrypts each chunk individually and concatenates the results
    """
    print("    [*] Processing chunked log file format", file=sys.stderr)

    decrypted_chunks = []
    offset = 0
    chunk_num = 0

    while offset < len(data):
        if offset + 2 > len(data):
            print(
                f"    [!] Incomplete chunk header at offset {offset}", file=sys.stderr
            )
            break

        # Read 2-byte little-endian length
        chunk_length = int.from_bytes(data[offset : offset + 2], byteorder="little")
        offset += 2

        if chunk_length == 0:
            print(
                f"    [*] Zero-length chunk at offset {offset - 2}, stopping",
                file=sys.stderr,
            )
            break

        if offset + chunk_length > len(data):
            print(
                f"    [!] Incomplete chunk data: need {chunk_length} bytes, have {len(data) - offset}",
                file=sys.stderr,
            )
            break

        chunk_data = data[offset : offset + chunk_length]
        offset += chunk_length

        # Decrypt this chunk individually
        try:
            decrypted_chunk = decrypt_aes_cbc(chunk_data, key, iv)
            decrypted_chunks.append(decrypted_chunk)
        except Exception as e:
            print(f"    [!] Chunk {chunk_num} decryption failed: {e}", file=sys.stderr)
            # Continue with other chunks

        chunk_num += 1

    print(
        f"    [*] Successfully decrypted {len(decrypted_chunks)}/{chunk_num} chunks",
        file=sys.stderr,
    )

    if len(decrypted_chunks) == 0:
        return b""

    # Concatenate decrypted chunks
    result = b"".join(decrypted_chunks)
    print(f"    [*] Final result: {len(result)} bytes", file=sys.stderr)
    return result


# ============================================================================
# CIPHER OPERATIONS
# ============================================================================


def decrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using AES-128-CBC with custom key and IV"""
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        return remove_padding(decrypted)
    except Exception as e:
        print(f"    [-] AES-CBC decryption failed: {e}", file=sys.stderr)
        raise


def encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using AES-128-CBC with custom key and IV"""
    try:
        # Add PKCS#7 padding
        padded_data = add_padding(data)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted
    except Exception as e:
        print(f"    [-] AES-CBC encryption failed: {e}", file=sys.stderr)
        raise


# Change to use custom seed implementation
def decrypt_seed_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using SEED-CBC with custom key and IV"""
    try:
        print(f"    [DEBUG] SEED key: {key.hex()}, IV: {iv.hex()}", file=sys.stderr)
        cipher = Cipher(SEED(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        return remove_padding(decrypted)
    except Exception as e:
        print(f"    [-] SEED-CBC decryption failed: {e}", file=sys.stderr)
        raise


# ============================================================================
# PADDING UTILITIES
# ============================================================================


def add_padding(data: bytes) -> bytes:
    """Add PKCS#7 padding to data for encryption"""
    block_size = 16  # AES block size
    padding_length = block_size - (len(data) % block_size)

    # Always add padding, even if data is already block-aligned
    padding = bytes([padding_length] * padding_length)
    return data + padding


def remove_padding(data: bytes) -> bytes:
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


# ============================================================================
# HIGH-LEVEL ORCHESTRATION FUNCTIONS
# ============================================================================


def decrypt_data(
    data: bytes,
    data_format: DataFormat,
    key_derivation: KeyDerivationMode,
    cipher_mode: CipherMode,
) -> bytes:
    try:
        # Step 1: Preprocess data based on format
        print(f"    [*] Preprocessing: {data_format.value}", file=sys.stderr)
        if data_format == DataFormat.BASE64:
            processed_data = preprocess_base64_decode(data)
        elif data_format == DataFormat.RAW:
            processed_data = preprocess_raw(data)
        elif data_format == DataFormat.CHUNKED:
            # For chunked format, we need the key first, then do special processing
            pass  # Handle below after key derivation
        else:
            raise ValueError(f"Unknown data format: {data_format}")

        # Step 2: Derive key/IV based on method
        print(f"    [*] Key derivation: {key_derivation.value}", file=sys.stderr)
        if key_derivation == KeyDerivationMode.XOR:
            key = derive_xor_key()
            iv = b"\x00" * 16  # Zero IV for XOR method
        elif key_derivation == KeyDerivationMode.EVP:
            key, iv = derive_evp_key()  # EVP method returns both
        elif key_derivation == KeyDerivationMode.STATIC:
            key, iv = derive_static_guid_key()  # Static GUID key
        else:
            raise ValueError(f"Unknown key derivation: {key_derivation}")

        print(
            f"    [*] Key: {key.hex()[:32]}..., IV: {iv.hex()[:32]}...", file=sys.stderr
        )

        # Handle chunked format after key derivation
        if data_format == DataFormat.CHUNKED:
            if cipher_mode == CipherMode.AES_CBC:
                return preprocess_chunked(data, key, iv)
            else:
                raise ValueError(
                    f"Chunked format only supports AES_CBC, not {cipher_mode}"
                )

        # Step 3: Decrypt using specified cipher
        print(f"    [*] Cipher: {cipher_mode.value}", file=sys.stderr)
        if cipher_mode == CipherMode.AES_CBC:
            return decrypt_aes_cbc(processed_data, key, iv)
        elif cipher_mode == CipherMode.SEED_CBC:
            # For SEED, use static key/IV (ignore derived ones)
            seed_key = derive_seed_static_key()
            seed_iv = derive_seed_static_iv()
            return decrypt_seed_cbc(processed_data, seed_key, seed_iv)
        else:
            raise ValueError(f"Unknown cipher mode: {cipher_mode}")

    except Exception as e:
        print(f"    [-] Decryption failed: {e}", file=sys.stderr)
        raise


def decrypt_file(
    file_path: Path,
    data_format: DataFormat,
    key_derivation: KeyDerivationMode,
    cipher_mode: CipherMode,
) -> DecryptResult:
    if not file_path.exists():
        print(f"[-] File not found: {file_path}")
        return False, None

    print(f"[*] Decrypting: {file_path}")
    print(
        f"    Format: {data_format.value}, Key: {key_derivation.value}, Cipher: {cipher_mode.value}"
    )

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        print(f"    [*] Input size: {len(data)} bytes")

        decrypted = decrypt_data(data, data_format, key_derivation, cipher_mode)
        return True, decrypted

    except Exception as e:
        print(f"    [-] Error: {e}")
        return False, None


# ============================================================================
# RSA KEY DECODING FUNCTIONS
# ============================================================================


def derive_custom_base64_alphabet(salt: int) -> str:
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


def custom_base64_decode(data: str, alphabet: str):
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


def decode_rsa_key(encoded_key: str, key_type: str):
    """Decode RSA key using the fully reverse-engineered algorithm"""
    print(f"Decoding {key_type}...")

    # Step 1: Filter every 5th character and XOR with 4
    filtered = ""
    for i, char in enumerate(encoded_key):
        if i % 5 != 0:  # Skip positions 0,5,10,15...
            filtered += chr(ord(char) ^ 4)
    print(f"  After filter/XOR: {len(filtered)} chars")

    # Step 2: Generate custom alphabet using param2=4 (hardcoded for RSA)
    alphabet = derive_custom_base64_alphabet(salt=4)
    print(f"  Custom alphabet: {alphabet}")

    # Step 3: Custom base64 decode
    decoded = custom_base64_decode(filtered, alphabet)
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


def verify_key_pair(public_key_path: Path, private_key_path: Path):
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


# Dont hardcode paths here
def decode_obfuscated_rsa_keys():
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
    decoded_public = decode_rsa_key(public_key, "PublicKey")
    decoded_private = decode_rsa_key(private_key, "PrivateKey")

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
        if verify_key_pair(public_key_path, private_key_path):
            print("[+] Key pair verified - modulus values match!")
        else:
            print("[-] WARNING: Key pair modulus mismatch!")
            success = 0

    return success == 2
