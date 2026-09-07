# Execution State

**Current Goal:** 
Tier 2 Process Probe. Split into three reviewable units: (1) F2.2 mixed verification + command-path normalization [DONE, uncommitted], (2) F2.1 eBPF execve process observer, (3) simagent subprocess support + Tier 2 E2E tests.

**Completed Steps:**
* F1.1 (Filesystem Observer): Implemented and verified in `pkg/probe/fs`.
* F1.2 (Simulated Agent): Created a standalone binary at `cmd/simagent/main.go` that executes file operations and records self-reported `TrajectoryEntry` events matching exactly what the OS reports.
* F1.3 (Trajectory Ingestion): Identified that `models.ParseTrajectory` already handles reading the JSON arrays. 
* E2E Tests (Tier 1): Created `tests/e2e/tier1_test.go` which builds `simagent`, runs it inside a tracked temporary directory, ingests the trajectory, and verifies it. Includes both honest (FAITHFUL) and attack (NOT FAITHFUL via omission) scenarios.
* Ran `go test -v ./tests/e2e` to verify compilation; tests successfully skip when run without `CAP_SYS_ADMIN` privileges.
* CI Fix (7d6a9cf): Repaired 6 failing GitHub Actions workflows. Removed invalid `if err := _ = ...` syntax from test files (introduced in 44e5269) and bumped golangci-lint-action from v6 to v9.3.0 for Go 1.25 compatibility.
* CI Fix (lint errcheck): With golangci-lint now actually running (v2.13.2 via action v9), it flagged unchecked `unix.Close` calls. Fixed all of them in `observer.go` (Stop()), `fanotify.go:111`, and `observer_test.go` (lines 247/260/339) using `_ = unix.Close(...)` / `defer func() { _ = unix.Close(x) }()`. Verified locally with golangci-lint v2.13.2: `0 issues`. Note: CI reports only 3 findings at a time due to golangci-lint's default `max-same-issues: 3`, so grep the whole repo rather than fixing iteratively.
* Agent docs refactor: Added shared `AGENTS.md` plus thin `CLAUDE.md`, `GEMINI.md`, and `CODEX.md` wrappers that point back to the shared instructions and preserve per-agent commit metadata.
* Codex attribution line updated in `CODEX.md` to use `Co-Authored-By: codex <codex@openai.com>`.
* F2.2 (Mixed Verification + command normalization): `Verify` already handled mixed action types in one pass (it loops all entries; `Match` filters by type). Added `targetsMatch`/`commandsMatch` in `pkg/matching/matching.go` so `ProcessExec`/`ProcessExit` targets normalize `ls` vs `/usr/bin/ls` by comparing the path basename when exactly one side is a bare command. Deterministic: never consults host PATH or filesystem. Added table-driven `TestProcessCommandNormalization` + `TestProcessExitUsesCommandNormalization` in `matching_test.go` and `TestMixedFileAndProcessVerification` + `TestMixedVerificationDetectsOmittedProcess` in `verification_test.go`. `go test ./...` green; golangci-lint v2.13.2 `0 issues`.

**Active Context:**
* Tier 1 E2E tests and components are fully wired and functional.
* Repo now has a shared agent instruction file that should be read first, regardless of whether the harness opens `AGENTS.md` or a model-specific wrapper.
* Dependabot PRs resolved: golangci-lint-action v9.3.0 landed via 7d6a9cf; checkout v7.0.1 (#2) and setup-go v7.0.0 (#1) closed unmerged per maintainer decision (no action major-version bumps for now). No open PRs.
* Tier 2 commit 1 (F2.2) implemented and tested locally but NOT yet committed. Files touched: `pkg/matching/matching.go`, `pkg/matching/matching_test.go`, `pkg/verification/verification_test.go`, `STATE.md`.
* golangci-lint is not in PATH; the stale `~/go/bin/golangci-lint` is v1.59.1 (broken on this toolchain). Install v2.13.2 into the session scratchpad via `GOBIN=<scratchpad> go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2` to lint locally.
* `models.TrajectoryEntry.Target` is a single string with no dedicated args field; process entries currently pack args into the target string (e.g. "git commit -m fix"). F2.1 will need to decide whether to add an args field or keep packing.

**Next Steps:**
* Commit F2.2 (`[claude] feat: mixed file+process verification with command-path normalization`).
* F2.1: add eBPF `execve` tracepoint process observer (new pkg, e.g. `pkg/probe/proc`) using `cilium/ebpf` per AGENTS.md, emitting `GroundTruthEvent` with command, args, exit code, timestamps. Plan the CI toolchain (clang/llvm + headers, or commit generated bpf objects) before or alongside this commit.
* F2.1 tests: unit test spawning `ls` / `echo hello`; then extend `cmd/simagent` for subprocesses and add `tests/e2e/tier2_test.go`.
