# Project Overview

This is a **research project** focused on understanding and re-hosting certain Korean banking software — starting with _AhnLab Safe Transaction (ASTx)_ — in order to run them **fully in the browser** via [CheerpX](https://leaningtech.com/cheerpx/).

While ASTx is our initial target, the approach is designed to be **generic**, so it can eventually support **multiple pieces of Korean banking/security software** that currently only run on native Linux or Windows environments.

---

## Goals

1. **Analyze** target `.deb` or other installer packages to:

   - Understand their dependencies and runtime requirements.
   - Identify system calls, kernel module usage, and hardware/VM checks.
   - Detect references to helper tools (e.g., `ethtool`, `hdparm`) and network endpoints.

2. **Package** the software inside a **custom 32-bit Debian (Bookworm) userland**, including:

   - Required shared libraries.
   - Shims for kernel modules and privileged operations.
   - Minimal runtime environment to satisfy the software.

3. **Run** the packaged environment inside CheerpX with:
   - A minimal filesystem image (`ext2`) exported from the Docker container.
   - Hooks to handle I/O, networking, and UI in the browser.

---

## Strategy

- **Static Analysis First**
  We unpack the `.deb` without installing it, list binaries, inspect linking and symbols, and extract key indicators (syscalls, `/dev` references, VM checks, etc.).

- **Shim / Emulation Layer**
  Instead of loading actual kernel modules or running privileged operations, we provide safe, simulated responses.

- **Controlled Build Environment**
  Development uses a multi-stage Docker build targeting `linux/i386` with Debian Bookworm as the base, matching CheerpX’s x86 Linux usermode execution.

- **Final Runtime Image**
  The production image is stripped of development tools and analysis scripts.
  Its filesystem is exported to `.ext2` for loading in CheerpX.

- **Browser Execution**
  CheerpX emulates x86 Linux usermode in WebAssembly/JavaScript, enabling the original banking software to run unmodified in a browser environment.

---

## Why This Matters

Many Korean banking applications are:

- **Platform-restricted** (x86 only).
- **Tightly bound** to specific system configurations.
- **Dependent** on legacy or privileged APIs.

By packaging and emulating them in the browser, we:

- Make them accessible across devices and architectures.
- Preserve their functionality for research and compatibility.
- Avoid intrusive changes to the host system.

---

## Current Status

- Target: **AhnLab Safe Transaction** `.deb` package.
- Static analysis tooling is implemented but being optimized for speed.
- Base Debian Bookworm i386 environment builds successfully.
- Next: integrate ASTx into a minimal runtime image and test in CheerpX.

---

## Development Notes

- Always run any Python code with uv, e.g. uv run python3 ...
- The CLI is accessible by invoking run with the package name, e.g.: uv run breakwater <command>
- Add or remove Python packages by invoking uv (uv add, uv remove) instead of directly editing pyproject.toml

---

Note: This is a research and interoperability project.
The software analyzed remains the property of its respective owners.\_
