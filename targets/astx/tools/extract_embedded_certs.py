#!/usr/bin/env python3
"""
Extract and deobfuscate embedded certificates from ASTx binary
Uses the same XOR + custom base64 algorithm as RSA keys
"""

from pathlib import Path

from crypto_helpers import deobfuscate_pem_data


def process_hex_file(hex_file_path, output_name):
    """Process a hex dump file and extract the PEM data"""

    print(f"\n[>] Processing {hex_file_path.name}")

    # Read hex data
    with open(hex_file_path, "r") as f:
        hex_string = f.read().strip()

    # Convert hex to ASCII string
    try:
        raw_bytes = bytes.fromhex(hex_string)
        ascii_string = raw_bytes.decode("ascii", errors="ignore")
        print(f"  Hex data: {len(hex_string)} chars -> {len(raw_bytes)} bytes")
    except ValueError as e:
        print(f"  [-] Invalid hex data: {e}")
        return None

    # Deobfuscate using the common algorithm
    result = deobfuscate_pem_data(ascii_string, output_name)

    return result


def main():
    # Define paths
    certs_dir = Path(__file__).parent.parent / "analysis" / "certs"
    output_dir = certs_dir / "extracted"
    output_dir.mkdir(exist_ok=True)

    # Certificate files to process
    cert_files = [
        ("ca_cert.txt", "CA Certificate"),
        ("server_cert.txt", "Server Certificate"),
        ("server_private_key.txt", "Server Private Key"),
    ]

    results = []

    for filename, description in cert_files:
        input_path = certs_dir / filename

        if not input_path.exists():
            print(f"[-] File not found: {input_path}")
            continue

        # Process the hex file
        pem_data = process_hex_file(input_path, description)

        if pem_data:
            # Determine output filename
            if "private" in filename.lower() or "key" in filename.lower():
                output_name = filename.replace(".txt", "_key.pem")
            else:
                output_name = filename.replace(".txt", ".pem")

            output_path = output_dir / output_name

            # Save PEM file
            with open(output_path, "w") as f:
                f.write(pem_data)

            print(f"  [+] Saved to: {output_path}")
            results.append((description, output_path))
        else:
            print(f"  [-] Failed to extract {description}")

    # Summary
    if results:
        print("\n[>] Extraction Summary")
        print("-" * 50)
        for desc, path in results:
            print(f"  {desc}: {path.name}")

            # Show certificate details using openssl
            if "Key" not in desc:
                try:
                    import subprocess

                    result = subprocess.run(
                        [
                            "openssl",
                            "x509",
                            "-in",
                            str(path),
                            "-noout",
                            "-subject",
                            "-issuer",
                            "-dates",
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    if result.returncode == 0:
                        for line in result.stdout.strip().split("\n"):
                            print(f"    {line}")
                except:
                    pass
    else:
        print("\n[-] No certificates extracted")


if __name__ == "__main__":
    main()
