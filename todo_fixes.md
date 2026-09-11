# Outstanding Fixes & Features

This document tracks the foundational audit of the Agent-Trace repository and the upcoming Tier 4.2 feature implementation.

### 1. The Command Normalization Flaw (F2.2)
* **The Problem:** The verifier used a basename-matching heuristic (`ls` matched `/usr/bin/ls`), which allowed a Substitution attack where an agent could execute a malicious binary in `/tmp/ls` but log it simply as `ls`.
* **Status:** **[DONE]** We deleted the normalization heuristic, enforced strict absolute-path matching, and updated the `simagent` to use `exec.LookPath` to report its exact execution path. Fully committed.

### 2. Truncated eBPF Arguments & CI Drift (F2.1)
* **The Problem:** The eBPF process probe captures command arguments using fixed 128-byte slots. An agent running `python -c "very long script..."` will have its payload truncated, blinding the verifier to a Substitution attack. Furthermore, the probe relies on local kernel headers instead of BPF CO-RE, causing random CI breakages when OS headers update.
* **Status:** **[UP NEXT]** We need to refactor `proc.bpf.c` to use a dynamic Ring Buffer to capture variable-length `argv` arrays (up to 8KB) without truncation, and port it to CO-RE using `vmlinux.h` for cross-kernel portability.

### 3. The Output Hash Race Condition (F4.1)
* **The Problem:** When an agent writes to a file, the `fanotify` observer waits for a 20ms `settleQuietWindow` after the file is closed before calculating the `OutputHash`. If the agent writes and then immediately deletes or renames the file within that 20ms window, the file is gone before the observer hashes it, causing a total loss of the output integrity evidence.
* **Status:** **[PENDING]** We need to re-evaluate whether to move output hashing entirely into an eBPF probe (capturing the exact write buffers synchronously) to eliminate the timer-based race condition.

### 4. InputHash for File Reads (Tier 4.2 Feature)
* **The Problem:** We need to hash files *before* the agent opens them to prevent Input Substitution. However, if the agent uses `os.WriteFile(O_TRUNC)`, the kernel truncates the file during the `open()` syscall, meaning a standard asynchronous `FAN_OPEN` event will arrive too late (the file will already be 0 bytes).
* **Status:** **[PENDING]** Once the 3 foundational flaws above are fixed, we will implement this using either Stateful Shadowing (pre-caching all file hashes) or `FAN_OPEN_PERM` (blocking the `open()` syscall in the kernel until we hash the file).
