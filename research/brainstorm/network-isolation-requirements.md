# ASTx Network Isolation Requirements for WebVM

## Summary

ASTx makes extensive network calls for telemetry, fingerprinting, and system discovery. Since WebVM cannot make outgoing network requests, these calls must be blocked or shimmed to prevent crashes and ensure functionality.

## External Network Calls (Must Block)

### HTTP/HTTPS Endpoints
- `curl ipinfo.io/ip -m 1` - Public IP detection for geolocation
- `http://ispt.ahnlab.com/status` - Telemetry data upload (encrypted)
- Likely additional AhnLab authentication/license servers

### Impact if Not Blocked
- `curl` calls will hang/timeout, potentially blocking ASTx startup
- Failed HTTP requests may trigger error handling that crashes the daemon
- Telemetry upload failures could put ASTx in degraded mode

## Local Network Discovery (Need Shimming)

### Commands That May Fail in WebVM
```bash
nm-tool | grep -i gateway                    # NetworkManager queries
route -n | grep 'UG[ \t]'                   # Routing table access  
arp -n | grep %                              # ARP table queries
ifconfig | grep -Eo 'inet (addr:)?...'      # Network interface enumeration
```

### Required Data for Fingerprinting
ASTx collects these network identifiers:
- Gateway IP (`GATEWAY_IP`) 
- Gateway MAC address (`GATEWAY_MAC`)
- Network interface MACs (`MAC_ETH0` through `MAC_ETH9`)
- Local IP addresses (`IP_ETH0`, `IP_ETH1`, `IP_ETH2`)
- Network interface names and states

## Blocking Strategies

### 1. DNS Blocking (Recommended)
```bash
# Add to run-astx script:
echo "127.0.0.1 ipinfo.io" >> /etc/hosts
echo "127.0.0.1 ispt.ahnlab.com" >> /etc/hosts
```

### 2. Command Shims
- Extend existing shim strategy to include `nm-tool`, `route`, `arp`
- Provide realistic fake responses that satisfy ASTx's fingerprinting
- Ensure responses are consistent across calls

### 3. Network Namespace Isolation
- Create isolated network namespace with no external connectivity
- Provide minimal loopback and container network interfaces

## Required Fake Network Data

For consistent fingerprinting, shims should provide:
```
Gateway IP: 172.18.0.1
Gateway MAC: 02:42:ac:12:00:01  
Local IP: 172.18.0.2
Local MAC: 02:42:ac:12:00:02
Interface: eth0
```

## Testing Approach

1. **Network isolation test**: Run ASTx with no network access, identify failure points
2. **Selective blocking**: Block external domains, test local network discovery
3. **Shim validation**: Ensure shimmed responses satisfy ASTx's data collection
4. **Functionality test**: Verify HTTPS daemon still starts and serves requests

## Implementation Priority

1. **High**: Block external HTTP calls (prevents hangs/timeouts)
2. **Medium**: Shim network discovery commands (prevents crashes)
3. **Low**: Consistent fake network identities (satisfies fingerprinting)

## WebVM-Specific Considerations

- WebVM network stack may behave differently than containers
- Some network discovery commands may not exist in WebVM environment
- Network interface names and addresses may be different
- Timing of network calls during startup is critical for daemon initialization