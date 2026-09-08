# Execution State

**Current Goal:**
Tier 2 Process Probe. Three reviewable units: (1) F2.2 mixed verification + command-path normalization [DONE, committed bc5373d], (2) F2.1 eBPF execve process observer [DONE, verified privileged, ready to commit], (3) simagent subprocess support + Tier 2 E2E tests [NOT STARTED].

**Completed Steps:**
* Tier 0 (F0.1-F0.4): data model, matching, verification, verdict. All five planned E2E attack scenarios exist as tests in `pkg/verification/verification_test.go` (honest, T1 omission, T2 fabrication, T3 substitution, combined). Run without privileges; audited green.
* F1.1 (Filesystem Observer): implemented in `pkg/probe/fs` (fanotify).
* F1.2 (Simulated Agent): `cmd/simagent/main.go` performs file operations and records matching `TrajectoryEntry` values. File actions only; no subprocess support.
* F1.3 (Trajectory Ingestion): `models.ParseTrajectory` handles it.
* E2E Tier 1: `tests/e2e/tier1_test.go` builds simagent, runs it in a tracked temp dir, verifies. Two scenarios only.
* CI Fix (7d6a9cf): repaired 6 failing workflows; bumped golangci-lint-action to v9.3.0.
* CI Fix (lint errcheck): fixed unchecked `unix.Close` calls in `observer.go`, `fanotify.go:111`, `observer_test.go`. golangci-lint v2.13.2 reports 0 issues. CI shows only 3 findings at a time (`max-same-issues: 3`), so grep the whole repo rather than fixing iteratively.
* Agent docs refactor: shared `AGENTS.md` plus thin `CLAUDE.md` / `GEMINI.md` / `CODEX.md` wrappers.
* F2.2 (Mixed verification + command normalization), committed bc5373d: `targetsMatch`/`commandsMatch` in `pkg/matching/matching.go` normalize `ls` vs `/usr/bin/ls` by basename when exactly one side is a bare command. Deterministic; never consults host PATH or filesystem. The fanotify parent-directory fallback is scoped to file actions only. Tests: `TestProcessCommandNormalization`, `TestProcessExitUsesCommandNormalization`, `TestMixedFileAndProcessVerification`, `TestMixedVerificationDetectsOmittedProcess`.
* F2.1 (eBPF process observer), verified privileged (`sudo go test -v ./pkg/probe/proc/...` all green, incl. new exit-code/timestamp tests), ready to commit: `pkg/probe/proc`. Non-CO-RE BPF C program on `syscalls/sys_enter_execve` + `syscalls/sys_enter_exit_group` + `sched/sched_process_exit`. argv stored as 12 fixed-width 128-byte slots (constant offsets, so the verifier bounds them without gymnastics). PERCPU_ARRAY heap to dodge the 512-byte stack limit. argv cached by TGID; `sys_enter_exit_group` updates that same cached record in-place with the exit code (glibc's exit()/_exit() path; a process killed by an uncaught signal never hits it, so `HasExitCode` stays false rather than fabricating 0); `sched_process_exit` emits the final replay with `ts_ns = bpf_ktime_get_ns()` stamped at actual exit, not at userspace read time. `go build`, `go vet`, golangci-lint v2.13.2 all clean (0 issues).
* Exit code and in-kernel timestamps wired end-to-end, not just captured: `models.GroundTruthEvent`/`TrajectoryEntry` gained `ExitCode *int32` (nil = unknown, same optionality pattern as the hash fields); `verification.go` gained `exitCodesAgree` with the same nil-agreement rule as `hashesAgree`, folded into the Corroborated/Mismatched decision — an agent claiming exit 0 on a command that actually failed is now a Mismatched, tested in `TestExitCodeMismatch`/`TestExitCodeNilTreatedAsAgreement`.
* Kernel timestamp conversion: `observer.go` computes `bootOffsetNs` once at `New()` from a matched `CLOCK_MONOTONIC`/`time.Now()` pair (`golang.org/x/sys/unix.ClockGettime`), then every event's `bpf_ktime_get_ns()` reading is converted via `wallNs = monoNs + bootOffsetNs` — removes ring-buffer drain latency from ground-truth timestamps. Tested in `TestObserver_ExitCodeAndTimestamps` (window check against wall-clock before/after, plus exec-before-exit ordering).
* Deleted `zz_verifierlog_debug_test.go` (debug scaffolding, marked "delete before committing" in its own header).

**Active Context:**
* `go test ./...` unprivileged is misleading: every fs, proc, and Tier 1 E2E test skips without root — only Tier 0 and matching/verification unit tests actually execute that way. Always confirm probe changes with `sudo go test -v ./...` before trusting green.
* Stale-artifact hazard remains open: `bpf_bpfel.o` / `bpf_bpfeb.o` are committed and CI has no clang, so editing `proc.bpf.c` without re-running `go generate ./pkg/probe/proc/...` silently ships the previous program. No CI guard for this yet (see Next Steps).
* Tier 1 E2E is incomplete vs plan: the plan lists four scenarios (honest, drop entry, add fake entry, swap filename). Only honest and omission exist at the E2E level. Fabrication and filename swap are covered at Tier 0 with synthetic data but not E2E.
* `models.TrajectoryEntry.Target` is still a single string with no dedicated args field; process entries pack args into the target (e.g. "git commit -m fix"). Unchanged by this pass.
* CI runs `sudo go test -v ./...`, so this commit is the first time the privileged proc tests execute on a GitHub Actions runner — watch the first run.
* `docs/` and `STATE.md` are gitignored; the plan and this file are local-only.
* golangci-lint is not in PATH; `~/go/bin/golangci-lint` is a stale v1.59.1 broken on this toolchain. Install v2.13.2 into a scratchpad via `GOBIN=<scratchpad> go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2` (it self-upgrades the toolchain to go1.26.8 via GOTOOLCHAIN on install, that's expected).

**Next Steps:**
1. Commit F2.1 (this session's work) with go.mod/go.sum (cilium/ebpf v0.19.0). Watch the first CI run.
2. Add a CI guard that re-runs `go generate ./...` and fails if the committed `.o`/`.go` bindings change, to catch the stale-artifact hazard.
3. Tier 2 unit 3: extend `cmd/simagent` with subprocess execution (os/exec), add `tests/e2e/tier2_test.go` (mixed file + process trajectory, honest and mutated — reuse the T1/T2/T3 attack shape from Tier 0/1).
4. Backfill the two missing Tier 1 E2E scenarios (fabrication, filename swap) to match the plan's four-scenario list.
