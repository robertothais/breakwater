# ASTx-UI Binary Archaeology

## Overview
The `astx-ui` binary contains unstripped symbols and debug assertions with full source paths, revealing the complete internal structure of AhnLab Safe Transaction's codebase.

## Source Code Structure

### Directory Layout
```
../ahnlab-confgmgr/
├── src/
│   └── aosconfmgr.cpp       # Configuration manager (line 0xfd0 assertion)

../ahnlab-util/
├── src/
│   ├── osinfo.cpp           # OS information gathering
│   └── util.cpp             # Utility functions

../ahnlab-crypto/
├── src/
│   ├── AhnCryptoMgr.cpp     # Cryptography manager
│   ├── EncHelper.cpp        # Encryption helpers
│   └── FileHelper.cpp       # File operations
```

### Core Components

#### Configuration Management
- **aosconfmgr.cpp**: Main configuration manager
- **iniparser.cpp**: INI file parsing
- Config paths:
  - `/opt/AhnLab/ASTx/ConfigFile/astx.conf`
  - `/opt/AhnLab/ASTx/userconfig.ini`
  - `/opt/AhnLab/ASTx/license.txt`

#### Security & Firewall
- **fwutil.cpp**: Firewall utilities
- **securityrule.cpp**: Security rule management
- **iprule.cpp**: IP filtering rules
- **portrule.cpp**: Port filtering rules
- **programrule.cpp**: Application whitelisting

#### Logging System
- **aoslogmgr.cpp**: Log management
- **logmanagergui.cpp**: GUI log viewer
- Debug functions:
  - `CleanUpDebugLog @ 080b8f30`
  - `logDebugUserMsg @ 080b93b0`
  - `logUIDebugUserMsg @ 080b9010`

#### GUI Components (Qt-based)
- **aboutdialog.cpp**: About dialog
- **alertdialog.cpp**: Alert notifications
- **firewallwindow.cpp**: Main firewall UI
- **guimanager.cpp**: GUI orchestration
- **systemtrayicon.cpp**: System tray integration
- **ipruledialog.cpp**: IP rule configuration
- **portruledialog.cpp**: Port rule configuration

#### IPC & Communication
- **ipcthread.cpp**: Inter-process communication thread
- Signal/slot mechanism for daemon communication

## Vulnerable/Interesting Functions

### Weak Cryptography
```
XorDecryption @ 080b2cd0        # XOR "encryption" (trivially broken)
Aes128Decrypt @ 080b60e0        # Custom AES implementation
Aes128Decrypt @ 080b61f0        # Another AES variant
DecryptFile @ 080b64f0          # File decryption
DoDecryption @ 080b6440         # Generic decryption wrapper
```

### Process Monitoring & Control
```
FillAllowedProcess @ 080b2c00   # Process whitelist management
FillOtherProcess @ 080b2b30     # Process blacklist management
getPIDofProcess @ 080be8c0      # Process tracking
ParseAndFillOtherProcess @ 080b28d0
ParseAndFillProcess @ 080b29d0
```

### Session Harvesting Functions
```
createUserSessionScript @ 08074fe7  # Creates shell script with harvested creds
getXDGRuntimeDir @ 080c863a        # Harvests XDG_RUNTIME_DIR
getXAuthority @ 080c855c           # Harvests XAUTHORITY
getDisplay @ 080c8444              # Harvests DISPLAY
harvestEnvFromUserProcesses @ getEnvironmentVariable  # Main harvesting function
```

## Security Issues Discovered

### 1. Unstripped Binary
- All function names exposed
- Internal architecture completely visible
- Debug assertions with source paths and line numbers
- Original filename: `createDefConfigXmlFile()` at line 0xfd0

### 2. Debug Information Leakage
Example assertion:
```c
__assert_fail("err == 0","../ahnlab-confgmgr/src/aosconfmgr.cpp",0xfd0,
              "bool createDefConfigXmlFile()");
```
Reveals:
- Exact source file paths
- Line numbers
- Function signatures
- Build directory structure

### 3. Weak Cryptography
- XOR "encryption" function present
- Custom AES implementations (often vulnerable)
- Multiple decrypt functions suggesting crypto complexity

### 4. Process Surveillance
- Comprehensive process monitoring
- PID tracking and management
- Process whitelist/blacklist enforcement

### 5. Credential Harvesting
- Extracts environment variables from user processes via `/proc/*/environ`
- Harvests X11 session credentials (DISPLAY, XAUTHORITY)
- Creates shell scripts with stolen credentials for privilege escalation

## Architecture Insights

### Cross-Platform Design
The presence of Qt widgets and duplicate functionality between daemon and UI suggests:
- Single codebase for Windows/Mac/Linux
- UI binary contains full daemon logic
- Debug build shipped to production

### IPC Architecture
- Qt signal/slot mechanism for UI-daemon communication
- `IPCThread` handles inter-process messaging
- `signalProcessIPCMsg @ 080c1940`
- `slotProcessIPCMsg @ 08079040`

### Build Information
- Built with Qt5 (`libQt5Widgets.so.5`)
- OpenSSL statically linked (numerous crypto functions)
- libxml2 for configuration parsing
- pthread for threading

## Exploitation Potential

### Attack Surface
1. **XOR Decryption**: Trivially reversible
2. **IPC Messages**: Qt signal/slot potentially exploitable
3. **Process Monitoring**: Can be evaded or spoofed
4. **Debug Logs**: May leak sensitive information
5. **Unstripped Symbols**: Complete roadmap for attackers

### Binary-as-a-Library Exploit

The unstripped symbols enable a critical exploitation technique - using the astx-ui binary itself as a crypto library. Even with PIE/ASLR enabled, the symbol table allows runtime resolution of function addresses:

```python
#!/usr/bin/env python3
# Use ASTx's own crypto against itself

import ctypes

class ASTxCrypto:
    def __init__(self):
        # Load the binary as a library - symbols enable this!
        self.lib = ctypes.CDLL("/opt/AhnLab/ASTx/astx-ui")
        
        # Symbol table lets us call non-exported functions by name
        self.xor_decrypt = self.lib.XorDecryption
        self.aes_decrypt = self.lib.Aes128Decrypt
        
    def decrypt_with_their_key(self, data):
        # Use their hardcoded XOR key
        self.lib.XorDecryption(data, len(data), b"KEY2ENCRYPT&DECRYPT")
        return data
        
    def decrypt_aes(self, encrypted):
        # Use their AES with their key derivation
        result = ctypes.create_string_buffer(len(encrypted))
        self.lib.Aes128Decrypt(encrypted, result, len(encrypted))
        return result.raw

# Decrypt their files using their own crypto functions!
crypto = ASTxCrypto()
```

**Why This Works**:
- Symbols act as a function directory inside the binary
- Dynamic loader resolves addresses even with PIE/ASLR
- Non-exported functions become callable through `dlsym()` or ctypes
- The binary essentially becomes a free crypto API for attackers

**Security Impact**:
- PIE/ASLR protection completely bypassed for named functions
- Attackers can use ASTx's own encryption to forge valid configs
- Perfect knowledge of crypto implementation without RE
- Can call internal functions that were never meant to be exposed

This transforms the security binary into an attacker's toolkit - like leaving the keys to the castle inside the castle gate.

### Credential Harvesting Abuse
The session harvesting mechanism could be repurposed by malware:
```bash
ps -u 'username' -o pid= | xargs -I{} cat /proc/{}/environ 2>/dev/null | 
tr '\0' '\n' | grep '^DISPLAY=' | cut -d= -f2 | sort | uniq -c | sort -nr
```

## Recommendations for Attackers/Researchers

1. **Focus on XorDecryption**: Likely contains hardcoded keys
2. **Analyze IPC protocol**: IPCThread communications may be unencrypted
3. **Debug log analysis**: May contain passwords or sensitive data
4. **Process whitelist bypass**: Understanding FillAllowedProcess logic
5. **Configuration tampering**: astx.conf and userconfig.ini are attack vectors

## Conclusion

The astx-ui binary is a goldmine for reverse engineering:
- Unstripped symbols provide complete function mapping
- Debug assertions reveal source structure
- Duplicate daemon functionality in UI doubles attack surface
- Weak crypto (XOR) and custom implementations
- Credential harvesting functions show attacker-like design

This appears to be a debug build accidentally shipped to production, providing unprecedented visibility into AhnLab's security software internals.