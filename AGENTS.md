# Agent-Trace Repository Guide

## ⚠️ Privileged Commands — NEVER run sudo headlessly

**NEVER attempt to run `sudo` in a background task or unattended terminal.** Sudo requires an interactive password and any attempt to do so will block, fail, or break the environment.

**Instead**: when a privileged test or command is needed (e.g., `sudo go test -v ./...` for eBPF/fanotify tests), **STOP** and ask the user to run it in their own terminal. Wait for them to paste back the output before continuing.

This applies to ALL privileged operations: `sudo go test`, `sudo go run`, any BPF/fanotify program requiring root, etc.

If your harness opened `CLAUDE.md`, `GEMINI.md`, or `CODEX.md` first, read this file next. This is the shared source of truth for all agents in this repo.

This repository contains the Agent Trajectory Faithfulness Verifier, written in Go. Its goal is to provide execution assurance for AI agent trajectories by comparing self-reported actions against ground-truth system probes.

## Agent Entry Points

- `CLAUDE.md`: Claude-specific wrapper and commit metadata.
- `GEMINI.md`: Gemini-specific wrapper and commit metadata.
- `CODEX.md`: Codex-specific wrapper and commit metadata.

## Codebase Gotchas & Architecture Rules

- No Large Autonomous Implementation: Implementations are done as focused, reviewable units. Tests grow incrementally alongside the implementation.
- eBPF Probes: For Tier 2+, we use `cilium/ebpf` for process probes.
- Testing Philosophy: Every tier MUST have at least one E2E semantic test that demonstrates the requirements. We strongly prefer table-driven `go test` for unit testing.
- Module Boundaries: Keep models (`TrajectoryEntry`, `GroundTruthEvent`, `ActionType`) strictly in `pkg/models`. Do not intermingle matching/verification logic into the data models.

## Documentation Index (Progressive Disclosure)

Do not assume all context is listed here. Search and load the following files when you need context on specific areas:

### Development Plan

- `docs/plan/01_protocol_architecture.md`: Overall working protocol and design architecture.
- `docs/plan/02_tiers_0_to_2.md`: Core logic, filesystem probes, and process probes requirements and tests.
- `docs/plan/03_tiers_3_to_6.md`: Network probes, content hashing, and attack simulation details.

### Related Work & Threat Models

- `docs/related_work/01_threat_models.md`: The taxonomy of threat models we address.
- `docs/related_work/02_execution_assurance.md`: Cryptographic evidence and faithful reproduction approaches.
- `docs/related_work/03_authorization_governance.md`: Pre-execution governance (AARM, AgentBound).
- `docs/related_work/04_anomaly_detection.md`: TraceAegis, TrajAD, and other detection methods.
- `docs/related_work/05_surveys_attacks_summary.md`: Documented attacks (e.g., HF intrusion) and summary table.

## SKILL.state Agent Protocol

You are operating under a state-centric execution protocol. Because the user frequently switches agents to manage context limits, you must not rely on conversational history. Instead, you must rely entirely on the explicit structured state persisted in `STATE.md`.

### Execution Loop

For every turn/request you receive, you MUST follow this loop:

1. Read State: Your first action should always be to read `STATE.md` to understand the current world state, past progress, and overarching goals.
2. Execute: Perform the requested actions or continue the work based on the "Next Steps" outlined in the state.
3. Update State: Before ending your turn, you MUST update `STATE.md` (overwriting it or modifying it) to reflect the new state.

### State Format

The `STATE.md` file should be kept concise and structured. It should ideally contain:

- Current Goal: The overarching objective.
- Completed Steps: What has been accomplished so far (briefly).
- Active Context: Current hypotheses, bugs found, critical files modified, or specific test results.
- Next Steps: The immediate next actions the agent should take on the next turn.

### Golden Rule

If it's not in `STATE.md`, the next agent won't know about it. Project all transient reasoning and discoveries into the structured state before you finish.

## Agentic CI & TDD

Shift Left via Agent Self-Correction: Before you attempt to commit any code or state that you have finished your turn, you MUST locally run `sudo go test -v ./...` and `go vet ./...` (or `golangci-lint run` if available). Act as your own IDE. Never commit broken code or ignore unhandled errors. If a test or linter fails, fix it immediately.

## Measurement Discipline

This project's central claim is a verdict (FAITHFUL / NOT FAITHFUL, MISMATCHED, CORROBORATED). Every such verdict is a measurement, and this is a research prototype for a paper, so the measurement has to survive scrutiny, not just pass locally. Full rationale and worked examples: `docs/methodology/being_data_driven.md`. Read it before designing a new experiment, probe, or E2E tier. In this repo, in practice:

- **Name the premise before building on it.** Before trusting a new probe or matcher on real trajectories, state the assumption you're least sure of (e.g. "curl opens exactly one connection per fetch" — false, see Tier 5 Happy-Eyeballs) and check it cheaply first.
- **Pre-register GO/STOP thresholds in the test/tool, before running it**, not after seeing the result. A verdict decided after the fact is a negotiation, not a measurement.
- **No verdict without a control.** A corroboration-rate change is only meaningful relative to the same rate measured on an unmodified baseline in the same run/environment. If there's no control, the tool should print UNJUDGED, not a verdict.
- **Validate new instrumentation against a known answer first.** A new probe's first real test should be against `simagent` with a fully scripted, known action sequence, before it's trusted on an unscripted trajectory.
- **Distinguish "not measured" from "measured zero."** Use an explicit `ok bool` or `*T`, never a bare zero default — this is why a nil `RequestHash` must not silently corroborate against a hashed ground-truth event (`pkg/verification/verification.go`).
- **Report `considered` / `evaluated` / `succeeded` together**, and count what couldn't be evaluated (skipped tiers, attach failures) instead of dropping it.
- **A proxy passing (e.g. 100% on the current E2E suite) is not the same as coverage of the threat model.** Check coverage against `docs/related_work/01_threat_models.md` periodically, not just test pass/fail.
- **Log abandoned approaches and corrected numbers** in the changelog section of `docs/methodology/being_data_driven.md` when they're relevant to a paper claim, so they aren't silently lost or re-attempted.
