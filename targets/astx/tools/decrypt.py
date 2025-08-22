#!/usr/bin/env python3
"""
ASTx Unified Decryption Tool
"""

import sys
import urllib.error
import urllib.request
from pathlib import Path

import typer
from crypto_helpers import (
    CipherMode,
    DataFormat,
    KeyDerivationMode,
    decode_obfuscated_rsa_keys,
    decrypt_data,
    decrypt_file,
)

app = typer.Typer(help="ASTx Unified Decryption Tool")
config_app = typer.Typer(help="Configuration file decryption")
app.add_typer(config_app, name="config")


def run_full_decryption():
    """Run complete decryption of all ASTx configuration files"""

    print("[!] ASTx Master Configuration Decryptor v1.0")
    print("=" * 55)

    success_count = 0
    total_count = 0

    # 1. Decrypt local AppConfig file
    print("\n[>] Phase 1: Local AppConfig Files")
    appconfig_path = Path("unpacked/rootfs/opt/AhnLab/ASTx/ConfigFile/appconfig.xml")
    match decrypt_file(
        appconfig_path, DataFormat.BASE64, KeyDerivationMode.XOR, CipherMode.AES_CBC
    ):
        case (True, data):
            save_decrypted_file(data, "appconfig.xml")
            success_count += 1
        case (False, _):
            pass

    total_count += 1

    # 2. Extract URLs from decrypted AppConfig and download remote files
    print("\n[>] Phase 2: Remote Files (from AppConfig URLs)")
    decrypted_appconfig = Path("analysis/decrypted/appconfig.xml")

    if decrypted_appconfig.exists():
        starter_url, version_url = extract_urls_from_appconfig(decrypted_appconfig)

        if starter_url:
            if download_and_decrypt(starter_url, "starter_ply_linux.downloaded.plist"):
                success_count += 1
            total_count += 1

        if version_url:
            if download_and_decrypt(version_url, "astx_ver_linux.downloaded.ini"):
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
    match decrypt_file(
        local_starter, DataFormat.BASE64, KeyDerivationMode.XOR, CipherMode.AES_CBC
    ):
        case (True, data):
            save_decrypted_file(data, "starter_ply_linux.plist")
            success_count += 1
        case (False, _):
            pass

    total_count += 1

    # Note: Skipping other config files (config.xml, suarez.conf.client)
    # as they may use different encryption methods

    # Summary
    print("\n" + "=" * 55)
    print(f"[+] Decryption Complete: {success_count}/{total_count} files processed")

    if success_count > 0:
        print("[+] Decrypted files saved to: analysis/decrypted/")

    return success_count == total_count


def extract_urls_from_appconfig(appconfig_file: Path):
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


@config_app.command("all")
def decrypt_all_configs():
    """
    Run complete decryption of all ASTx configuration files.

    Identical behavior to original decrypt_configs.py script.
    """
    try:
        success = run_full_decryption()

        # After full decryption, attempt RSA key decoding
        if success:
            decode_obfuscated_rsa_keys()

        return 0 if success else 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def download_and_decrypt(url: str, output_name: str, key: bytes | None = None):
    """Download encrypted file from URL and decrypt it"""

    print(f"[*] Downloading: {url}")

    try:
        with urllib.request.urlopen(url) as response:
            encrypted_data = response.read()

        print(f"    [+] Downloaded {len(encrypted_data)} bytes")

        decrypted_data = decrypt_data(
            encrypted_data, DataFormat.BASE64, KeyDerivationMode.XOR, CipherMode.AES_CBC
        )

        save_decrypted_file(decrypted_data, output_name)
        return True

    except urllib.error.URLError as e:
        print(f"    [-] Download failed: {e}")
        return False
    except Exception as e:
        print(f"    [-] Error downloading/decrypting {url}: {e}")
        return False


def save_decrypted_file(content: bytes, filename: str) -> Path:
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


@config_app.command("file")
def decrypt(
    file: str = typer.Argument(..., help="Configuration file to decrypt"),
    data_format: DataFormat = typer.Option(
        DataFormat.RAW, "--format", help="Data format: raw or base64"
    ),
    key_derivation: KeyDerivationMode = typer.Option(
        KeyDerivationMode.STATIC, "--key", help="Key derivation: xor, evp, or static"
    ),
    cipher_mode: CipherMode = typer.Option(
        CipherMode.AES_CBC, "--cipher", help="Cipher mode: aes_cbc or seed_cbc"
    ),
):
    """
    Decrypt a single configuration file.

    All parameters can be specified independently for maximum flexibility.
    """
    try:
        file_path = Path(file)
        status = 0
        match decrypt_file(file_path, data_format, key_derivation, cipher_mode):
            case (True, content):
                print(f"[+] Successfully decrypted: {file}")
                print(
                    f"    Format: {data_format.value}, Key: {key_derivation.value}, Cipher: {cipher_mode.value}"
                )
                
                # Truncate output to 4KB for display
                MAX_DISPLAY_SIZE = 4096
                display_content = content[:MAX_DISPLAY_SIZE]
                truncated = len(content) > MAX_DISPLAY_SIZE
                
                print(display_content.hex(" "))
                print(display_content.decode("utf-8", errors="ignore"))
                
                if truncated:
                    print(f"... [output truncated, showing {MAX_DISPLAY_SIZE}/{len(content)} bytes]")
            case (False, _):
                print(f"[-] Failed to decrypt: {file}")
                status = 1

        return status

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


@app.callback()
def main():
    """
    ASTx Unified Decryption Tool

    Supports configuration file decryption with the same algorithms
    and behavior as the original decrypt_configs.py script.
    """
    pass


if __name__ == "__main__":
    app()
