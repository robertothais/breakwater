# ASTx MAC Address Forgery Detection Analysis

## Overview

ASTx implements sophisticated MAC address forgery detection as an anti-VM and anti-tampering measure. This system compares hardware-burned permanent MAC addresses against currently configured MAC addresses to detect virtualization, MAC spoofing, or hardware substitution.

## Detection Chain

### 1. Network Interface Discovery
**Function**: `getNetworkInterfaceList()`  
**Command**: 
```bash
ifconfig | cut -d' ' -f1 | sort | uniq -u | awk -F: '{print $1;}' | grep -v lo | grep -v virbr
```
**Purpose**: Discovers available network interfaces (eth0, eth1, etc.)

### 2. Permanent MAC Collection  
**Function**: `getOriginalMACAddressList()`  
**Method**: Executes `ethtool -P <interface>` for each interface  
**Purpose**: Retrieves hardware-burned permanent MAC addresses from network card firmware  
**Example**: `ethtool -P eth0 | cut -d' ' -f3` → `00:50:56:c0:00:01`

### 3. Current MAC Collection
**Function**: `getMACAddressList()`  
**Method**: Direct file I/O on `/sys/class/net/<interface>/address`  
**Purpose**: Reads currently configured/active MAC addresses  
**Implementation**: Uses `fopen()` and `fgets()` - no shell commands

### 4. Forgery Detection
**Function**: `FUN_08118022()` (renamed to `checkNetworkHardwareConsistency()`)  
**Logic**: Compares permanent vs current MAC addresses using `strcmp()`  
**Output**: Sets flags like `FORGERY_MAC_ETH0_YN`, `FORGERY_MAC_ETH1_YN`  
- `"N"` = No forgery detected (MACs match)
- `"Y"` = Yes, forgery detected (MACs differ)

## Detection Triggers

The system flags forgery when:
- **VM Detection**: Virtual interfaces lack permanent hardware MACs
- **MAC Spoofing**: User changes active MAC but hardware returns original
- **Hardware Substitution**: Different network card with different permanent MAC
- **Container/Docker**: Virtual networking assigns different MACs

## Docker Bypass Strategy

### Problem
- Docker containers get virtual MAC addresses (e.g., `02:42:xx:xx:xx:xx`)
- `ethtool -P` on virtual interfaces returns empty/error
- Comparison fails: empty permanent MAC ≠ virtual current MAC

### Solution
1. **Ethtool Shim**: Provide fake permanent MAC addresses
2. **Matching Docker MAC**: Set container MAC to match shim output

### Implementation

**Ethtool Shim** (`/usr/local/bin/ethtool`):
```bash
#!/usr/bin/env bash

if [[ "$1" == "-P" ]]; then
  interface="$2"
  case "$interface" in
    eth0) echo "Permanent address: 00:50:56:c0:00:01" ;;
    eth1) echo "Permanent address: 00:50:56:c0:00:02" ;;
    eth2) echo "Permanent address: 00:50:56:c0:00:03" ;;
    *) echo "Permanent address: 00:50:56:c0:00:08" ;;
  esac
  exit 0
fi

# Handle other ethtool flags...
```

**Docker Command**:
```bash
docker run --mac-address 00:50:56:c0:00:01 your-container
```

### Verification
Check all three steps return consistent results:
```bash
# 1. Interface discovery
ifconfig | cut -d' ' -f1 | sort | uniq -u | awk -F: '{print $1;}' | grep -v lo | grep -v virbr

# 2. Permanent MAC (via shim)
ethtool -P eth0

# 3. Current MAC (Docker sets this)
cat /sys/class/net/eth0/address
```

All should return `eth0` exists with MAC `00:50:56:c0:00:01`.

## Log Evidence

From decrypted ASTx debug logs:
```
[Info] setMacModifiedYN index : 1, field : FORGERY_MAC_ETH0_YN
[Info] setMacModifiedYN orgcount : 0 index : 1
[Info] setMacModifiedYN count    : 1 index : 1
[Info] getOrgMadrList cmd : ethtool -P eth0 | cut -d' ' -f3
[Info] getMadrList i : 0, NetWorkName : eth0
```

This shows the system actively monitoring and comparing MAC addresses for each network interface.

## Security Impact

This detection mechanism makes ASTx extremely difficult to run in:
- Virtual machines (VMware, VirtualBox, etc.)
- Containers (Docker, LXC, etc.)  
- Cloud environments
- Systems with MAC address randomization enabled

It's a sophisticated anti-analysis and anti-circumvention measure typical of Korean banking security software.