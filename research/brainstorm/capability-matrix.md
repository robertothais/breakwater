# Capability Matrix: Motivation, Taxonomy, and Design

This note proposes a first-class, machine-readable “capability matrix” for Korean banking/security software. It captures what each package needs from the system so we can prioritize shims, build minimal runtime images, and run targets safely inside CheerpX.

## Executive Summary
- Problem: Target packages rely on diverse, privileged, and legacy environment features (helpers, /proc/sysfs, netlink, kernel modules, VM checks). This complexity blocks portability and makes ad-hoc shimming brittle.
- Solution: Codify capabilities as a stable schema per canonical package with evidence (static/dynamic), confidence, and shim status. Use it to drive priorities, builds, policies, and tests.
- Outcome: A living artifact that turns reverse-engineering insights into reproducible, auditable decisions, improving coverage, safety, and maintainability.

## Rationale
- Prioritization: Focus on the few capabilities that unlock the most services (impact scoring + greedy set cover), rather than chasing package-by-package specifics.
- Maintainability: As vendors ship updates, we update evidence and confidence without re-deriving everything. The matrix abstracts from “how” to “what”.
- Risk and Security: Capabilities map directly to browser policy (files, IPC, network). We can enforce least privilege and log deviations.
- Reproducibility: Encodes provenance (static/dynamic detectors) and confidence; enables peer review and regression tracking.
- Communication: A shared language for engineers and stakeholders to discuss tradeoffs (e.g., acceptable VM-fingerprints vs strict fidelity).

## Scope and Definitions
- Capability: A normalized, portable statement about an observable requirement or behavior (e.g., “reads MAC address”, “invokes dmidecode”, “opens a netlink socket”).
- Levels:
  - required: failure expected without it.
  - optional: degraded UX but still functional.
  - negotiable: works with plausible emulation or alternative pathway.
- Metadata: privilege (user/elevated), emulate strategy, shim status, evidence, confidence, notes.

## Taxonomy Discussion
Capabilities can be categorized along multiple dimensions. We recommend a hybrid taxonomy that balances observability and intent.

- Dimensions (orthogonal attributes):
  - Privilege level: user vs elevated (CAPs/root/ioctl).
  - Observability: static (strings/opcodes/imports), dynamic (syscalls/exec/paths), network (endpoints/TLS pins).
  - Spoofability: easy (pure reads), moderate (timing-sensitive), hard (kernel ioctls, hardware IDs).
  - Determinism: deterministic vs environment-dependent (timing, entropy, network reachability).
  - Sensitivity: security-critical (cert validation paths, anti-tamper) vs low-risk (banner reads).

- Taxonomy variants (and why a hybrid):
  - Resource-oriented (files/syscalls/helpers):
    - Pros: maps directly to shims and policies; easy to detect.
    - Cons: can obscure the “why” (e.g., disk info for anti-VM checks vs licensing).
  - Function-oriented (intent/goal):
    - Pros: clearer requirements (e.g., “device fingerprinting”, “cert store access”).
    - Cons: harder to detect purely; needs interpretation.
  - Threat-driven (checks/defenses):
    - Pros: highlights adversarial behaviors (anti-VM, anti-debug, exfil paths).
    - Cons: overlaps with function-oriented and needs careful labeling.

We adopt a hybrid: resource-oriented capability IDs grouped by function-oriented families, with a “threat” tag where applicable.

## Normalized Capability Families (initial)
- System Info
  - CPU: cpuid; /proc/cpuinfo; DMI/SMBIOS reads.
  - BIOS/DMI: dmidecode; /sys/class/dmi/id/*.
  - Disk: hdparm; /sys/block/*; HDIO* ioctls.
  - NIC: ethtool -P; /sys/class/net/*; MAC reads.
- Kernel/Privilege
  - Netlink sockets; nft/iptables exec; modprobe; /proc/modules; privileged ioctls.
- Environment/VM Checks
  - Hypervisor bit; vendor strings; DMI/VM MAC patterns; timing/rdtsc; perf_event_open.
- Filesystem/OS
  - Reads under /proc, /sys, /dev; systemctl/loginctl; DBus service discovery.
- Network
  - Specific endpoints/domains; proxy detection; TLS pinning.
- Crypto/Cert
  - Engine linkage (OpenSSL/NSS/GnuTLS); cert store access; PKCS#11 hooks.
- UI/IPC
  - X11/Wayland; GTK/QT; shared memory; pipes; simple IPC.

Each atomic capability gets a stable ID (e.g., sysinfo.nic.mac_address) and can be tagged as required/optional/negotiable.

## Technical Design (Schema)
Represent each canonical package in YAML with versions, capabilities, evidence, and status.

Example: catalog/capabilities/ahnlab_safe_transaction.yaml

```yaml
package: AhnLab Safe Transaction
versions:
  - range: ">=1.3.0"
    capabilities:
      - id: sysinfo.cpu.cpuid
        required: true
        privilege: user
        emulate_strategy: deterministic-fingerprint
        shim_status: planned
        evidence:
          - type: static
            signal: opcode
            detail: "CPUID instruction detected"
          - type: dynamic
            signal: exec
            detail: "/usr/bin/cpuid"
        confidence: high
      - id: sysinfo.nic.mac_address
        required: true
        privilege: user
        emulate_strategy: stable-mac
        shim_status: implemented
        evidence:
          - type: dynamic
            signal: ethtool
            detail: "ethtool -P eth0"
        confidence: high
      - id: env.vm_fingerprint_checks
        required: optional
        privilege: user
        emulate_strategy: plausible-dmi
        shim_status: planned
        evidence:
          - type: static
            signal: string
            detail: "VBOX, QEMU, VMware substrings"
        confidence: medium
    notes: "Falls back to /proc if helpers absent."
```

Field meanings
- id: stable identifier (namespaced).
- required: required | optional | negotiable.
- privilege: user | elevated.
- emulate_strategy: deterministic | random-but-stable | passthrough | deny.
- shim_status: missing | planned | implemented | verified.
- evidence: static/dynamic/network with signal + detail.
- confidence: low | medium | high.
- notes: free text.

## Population Pipeline
- Static detection (fast, broad):
  - ELF parsing: DT_NEEDED, imported symbols, section references.
  - Opcode scan: CPUID/RDTSC.
  - YARA-like string rules: helper names (ethtool, hdparm, dmidecode, iptables), /proc and /sys paths, DBus names.
  - Linking hints: NSS/OpenSSL/GnuTLS/X11/DBus.
- Dynamic tracing (precise, targeted):
  - Run in i386 Bookworm container with shims disabled to observe natural behavior.
  - strace/bpftrace: syscalls, ioctl, file paths, sockets, netlink.
  - Process exec capture: helper binaries + args.
  - Network instrumentation: endpoints, SNI, TLS pins (in dev harness).
- Normalization + scoring:
  - Map raw signals → capabilities; compute confidence (corroborated signals = high).
  - Bucket by version ranges when multiple releases analyzed.
- Writer:
  - Emit/update YAML under catalog/capabilities/*.yaml with provenance and timestamps.

## Integration With the Pipeline
- Prioritization
  - Join with usage stats to compute impact per capability; run a greedy set-cover over capabilities to unlock X% of services with minimal shims.
- Build
  - Derive shims/helpers to include per target set; generate per-capability config (e.g., deterministic fingerprints).
- Browser Policy
  - Produce allowlists (files/IPC/endpoints) from capabilities; enforce least privilege and log deviations.
- Testing
  - Auto-generate conformance tests per implemented capability (e.g., ethtool -P returns stable MAC).

## Visualization
- Capability heatmap: packages × capabilities; color by required/optional and shim status; sort by impact.
- Overlay implemented vs missing to show blockers; drill-down to evidence and traces.

## Roadmap and Open Questions
- Phase 1: Finalize taxonomy and schema (<50 capability IDs to start).
- Phase 2: Implement detectors and normalizer; run across top-used packages; hand-review.
- Phase 3: Wire into build to generate shim lists/configs for top N packages.
- Phase 4: Add statistical significance (Fisher/FDR) and coverage curves to guide priorities.

Open questions
- Granularity: how fine-grained should capabilities be (e.g., “reads NIC MAC” vs “reads any NIC attribute”)?
- Equivalence: when two resources serve the same function (dmidecode vs /sys), should they be separate or a single capability with variants?
- Policy defaults: how strict should deny-by-default be in early research vs later demonstrations?

## Benefits
- Converts reverse-engineering artifacts into a durable, reviewable plan that drives shims, builds, and risk decisions.
- Quantifies progress (e.g., “8/12 high-impact capabilities implemented; projected coverage 72%”).
- Scales to new packages/versions without starting over.
