#!/usr/bin/env -S uv --quiet run --script
"""
ASTx Encrypted Log Tailer

Tails encrypted ASTx log files and decrypts chunks in real-time.
Uses chunked format: 2-byte length + encrypted chunk (repeat).
"""

import logging
import re
import sys
import time
from pathlib import Path

import typer
from crypto_helpers import (
    CipherMode,
    DataFormat,
    KeyDerivationMode,
    configure_crypto_logging,
    decrypt_data,
)


def colorize_function_name(line: str, target_function: str = None) -> str:
    """Colorize the fourth bracketed element (function name) in red if it matches target"""
    if not target_function:
        return line

    # Use regex to find and replace the fourth bracketed element only if it matches target
    # Pattern: [timestamp][level][thread][function_name] -> [timestamp][level][thread][RED function_name RESET]
    pattern = r"(\[[^\]]+\]\[[^\]]+\]\[[^\]]+\]\[)([^\]]+)(\])"

    def replace_func(match):
        prefix = match.group(1)  # [2025-08-23 04:57:08][Info][t1146096448][
        function_name = match.group(2)  # ExitIPMonitor
        suffix = match.group(3)  # ]

        # Only colorize if it matches the target function
        if function_name == target_function:
            # ANSI color codes: \033[31m = red, \033[0m = reset
            return f"{prefix}\033[31m{function_name}\033[0m{suffix}"
        else:
            return match.group(0)  # Return unchanged

    return re.sub(pattern, replace_func, line)


class EncryptedLogTailer:
    def __init__(self, log_path: Path, target_function: str = None):
        self.log_path = log_path
        self.file_pos = 0
        self.partial_chunk = b""
        self.target_function = target_function

    def tail_chunks(self):
        """Read and decrypt new chunks as they arrive"""
        if not self.log_path.exists():
            return []

        with open(self.log_path, "rb") as f:
            f.seek(self.file_pos)
            new_data = f.read()
            self.file_pos = f.tell()

        if not new_data:
            return []

        # Combine with any partial chunk from previous read
        data = self.partial_chunk + new_data
        self.partial_chunk = b""

        chunks = []
        offset = 0

        while offset < len(data):
            # Need at least 2 bytes for length header
            if offset + 2 > len(data):
                self.partial_chunk = data[offset:]
                break

            chunk_length = int.from_bytes(data[offset : offset + 2], byteorder="little")
            offset += 2

            if chunk_length == 0:
                break

            # Check if we have the complete chunk
            if offset + chunk_length > len(data):
                # Partial chunk - save for next iteration
                self.partial_chunk = data[offset - 2 :]  # Include length header
                break

            chunk_data = data[offset : offset + chunk_length]
            offset += chunk_length

            # Decrypt chunk
            try:
                decrypted = decrypt_data(
                    chunk_data,
                    DataFormat.RAW,  # Chunks are already extracted
                    KeyDerivationMode.STATIC,
                    CipherMode.AES_CBC,
                )
                chunks.append(decrypted.decode("utf-8", errors="replace"))
            except Exception as e:
                print(f"[!] Failed to decrypt chunk: {e}", file=sys.stderr)

        return chunks

    def tail_forever(self):
        """Continuously tail the log file"""
        print(f"[*] Tailing encrypted log: {self.log_path}")
        print(f"[*] Press Ctrl+C to stop")
        print("-" * 60)

        try:
            while True:
                chunks = self.tail_chunks()
                for chunk in chunks:
                    # Optionally colorize each decrypted chunk
                    clean_chunk = chunk.rstrip("\n\r")
                    if clean_chunk:  # Only print non-empty lines
                        colored_chunk = colorize_function_name(
                            clean_chunk, self.target_function
                        )
                        print(colored_chunk)

                if not chunks:
                    time.sleep(0.1)  # Brief pause if no new data

        except KeyboardInterrupt:
            print(f"\n[*] Stopped tailing {self.log_path}")


def main(
    log_file: str = typer.Argument(..., help="Path to encrypted log file to tail"),
    debug: bool = typer.Option(False, "--debug", help="Show crypto debug output"),
    colorize: str = typer.Option(
        None, "--colorize", "-c", help="Highlight specific function name in red"
    ),
):
    """Tail encrypted ASTx log files and decrypt chunks in real-time"""

    # Setup quiet crypto logging by default, debug if requested
    crypto_level = logging.DEBUG if debug else logging.ERROR
    configure_crypto_logging(crypto_level)

    log_path = Path(log_file)

    if not log_path.exists():
        print(f"Error: Log file does not exist: {log_path}")
        sys.exit(1)

    tailer = EncryptedLogTailer(log_path, target_function=colorize)
    tailer.tail_forever()


if __name__ == "__main__":
    typer.run(main)
