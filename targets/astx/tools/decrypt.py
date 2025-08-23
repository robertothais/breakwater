#!/usr/bin/env -S uv --quiet run --script
"""
ASTx Unified Decryption Tool
"""

import logging
import sys
import urllib.error
import urllib.request
from pathlib import Path

import typer
from crypto_helpers import (
    CipherMode,
    DataFormat,
    KeyDerivationMode,
    configure_crypto_logging,
    decode_obfuscated_rsa_keys,
    decrypt_data,
    decrypt_file,
)

# Common arguments
VerboseOption = typer.Option(
    0,
    "--verbose",
    "-v",
    count=True,
    help="Increase verbosity (-v: progress, -vv: debug)",
)
QuietOption = typer.Option(
    False, "--quiet", "-q", help="Suppress all output except content and errors"
)

# Main logger for decrypt operations
logger = logging.getLogger("astx.decrypt")

app = typer.Typer(help="ASTx Unified Decryption Tool")
config_app = typer.Typer(help="Configuration file decryption")
app.add_typer(config_app, name="config")


def run_full_decryption():
    """Run complete decryption of all ASTx configuration files"""

    logger.info("[!] ASTx Master Configuration Decryptor v1.0")
    logger.info("=" * 55)

    success_count = 0
    total_count = 0

    # 1. Decrypt local AppConfig file
    logger.info("")
    logger.info("[>] Phase 1: Local AppConfig Files")
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
    logger.info("")
    logger.info("[>] Phase 2: Remote Files (from AppConfig URLs)")
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
        logger.warning("    [!] AppConfig not decrypted, skipping remote downloads")
        total_count += 2

    # 3. Decrypt local starter policy file
    logger.info("")
    logger.info("[>] Phase 3: Local Policy Files")
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
    logger.info("")
    logger.info("=" * 55)
    logger.info(
        "[+] Decryption Complete: %d/%d files processed", success_count, total_count
    )

    if success_count > 0:
        logger.info("[+] Decrypted files saved to: analysis/decrypted/")

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
        logger.error("    [-] Error extracting URLs from AppConfig: %s", e)
        return None, None


@config_app.command("all")
def decrypt_all_configs(
    verbose: int = VerboseOption,
    quiet: bool = QuietOption,
):
    """
    Run complete decryption of all ASTx configuration files.

    Identical behavior to original decrypt_configs.py script.
    """
    try:
        # Setup logging for the full decryption routine
        logger = setup_logging_and_verbosity(verbose, quiet, False)

        success = run_full_decryption()

        # After full decryption, attempt RSA key decoding
        if success:
            decode_obfuscated_rsa_keys()

        return 0 if success else 1

    except Exception as e:
        error_logger = logging.getLogger("astx.decrypt")
        error_logger.error("Error: %s", e)
        return 1


def download_and_decrypt(url: str, output_name: str, key: bytes | None = None):
    """Download encrypted file from URL and decrypt it"""

    logger.info("[*] Downloading: %s", url)

    try:
        with urllib.request.urlopen(url) as response:
            encrypted_data = response.read()

        logger.info("    [+] Downloaded %d bytes", len(encrypted_data))

        decrypted_data = decrypt_data(
            encrypted_data, DataFormat.BASE64, KeyDerivationMode.XOR, CipherMode.AES_CBC
        )

        save_decrypted_file(decrypted_data, output_name)
        return True

    except urllib.error.URLError as e:
        logger.error("    [-] Download failed: %s", e)
        return False
    except Exception as e:
        logger.error("    [-] Error downloading/decrypting %s: %s", url, e)
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
        logger.info("[+] Saved decrypted text file: %s", output_file)
    except UnicodeDecodeError:
        # Save as binary if text decoding fails
        with open(output_file, "wb") as f:
            f.write(content)
        logger.info("[+] Saved decrypted binary file: %s", output_file)

    return output_file


def display_content(content: bytes, quiet: bool = False):
    """Display content to stdout, with optional binary content info to stderr"""

    # Try to decode as text
    try:
        text_content = content.decode("utf-8")
        print(text_content, end="")  # No extra newline
    except UnicodeDecodeError:
        # For binary content, show info to stderr and raw content to stdout
        if not quiet:
            print(f"[*] Binary content ({len(content)} bytes)", file=sys.stderr)
            if len(content) > 0:
                print(f"[*] First 64 bytes: {content[:64].hex(' ')}", file=sys.stderr)
        # Output raw binary to stdout for redirection
        sys.stdout.buffer.write(content)


def setup_logging_and_verbosity(
    verbose: int = 0, quiet: bool = False, is_redirected: bool = False
):
    """Setup logging levels based on verbosity and output redirection"""

    # Setup main decrypt logger
    decrypt_logger = logging.getLogger("astx.decrypt")

    if quiet or is_redirected:
        # Completely quiet - errors only
        crypto_level = logging.ERROR
        decrypt_level = logging.ERROR
    elif verbose == 0:
        # Default - basic status messages
        crypto_level = logging.WARNING
        decrypt_level = logging.INFO
    elif verbose == 1:
        # -v: Show crypto progress
        crypto_level = logging.INFO
        decrypt_level = logging.INFO
    else:
        # -vv: Full debug
        crypto_level = logging.DEBUG
        decrypt_level = logging.DEBUG

    # Configure crypto logging
    configure_crypto_logging(crypto_level)

    # Configure decrypt logging
    decrypt_logger.setLevel(decrypt_level)
    if not decrypt_logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        decrypt_logger.addHandler(handler)

    return decrypt_logger


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
        CipherMode.AES_CBC, "--cipher", help="Cipher mode: aes_cbc"
    ),
    verbose: int = VerboseOption,
    quiet: bool = QuietOption,
):
    """
    Decrypt a single configuration file.

    All parameters can be specified independently for maximum flexibility.
    Output is sent to stdout for easy redirection.
    """
    try:
        # Detect if output is being redirected
        is_redirected = not sys.stdout.isatty()

        # Setup logging based on verbosity and redirection
        logger = setup_logging_and_verbosity(verbose, quiet, is_redirected)

        file_path = Path(file)
        status = 0
        match decrypt_file(file_path, data_format, key_derivation, cipher_mode):
            case (True, content):
                # Status info via logging
                logger.info("[+] Successfully decrypted: %s", file)
                logger.info(
                    "    Format: %s, Key: %s, Cipher: %s",
                    data_format.value,
                    key_derivation.value,
                    cipher_mode.value,
                )
                logger.info("    Size: %d bytes", len(content))

                # Content to stdout (for redirection)
                display_content(content, quiet=quiet or is_redirected)

            case (False, _):
                logger.error("[-] Failed to decrypt: %s", file)
                status = 1

        return status

    except Exception as e:
        # Always log errors regardless of verbosity
        error_logger = logging.getLogger("astx.decrypt")
        error_logger.error("Error: %s", e)
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
