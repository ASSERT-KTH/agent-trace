# Agent-Trace: Trajectory Faithfulness Verifier

[![Tests](https://github.com/ASSERT-KTH/agent-trace/actions/workflows/test.yml/badge.svg)](https://github.com/ASSERT-KTH/agent-trace/actions/workflows/test.yml)

AI agents self-report their actions through trajectories. But what if the agent is compromised, hallucinating, or actively hiding malicious actions?

**Agent-Trace** is a verification engine that assesses the *faithfulness* of AI agent trajectories by cross-referencing their self-reported logs against independent, host-level OS probes.

## How it works

An agent produces a **trajectory**: a JSON log of the actions it claims to have taken (file opens, writes, process executions, exits, and so on). Independently, host-level probes observe what actually happened on the system and produce a **ground truth** log of the same shape.

`pkg/verification` compares the two and classifies every entry into one of four sets:

- **Corroborated** — a trajectory entry matches an observed ground-truth event.
- **Unwitnessed** — the agent claims an action no probe observed (fabrication).
- **Unrecorded** — a probe observed an action the agent never reported (omission).
- **Mismatched** — an action is claimed and observed, but details disagree (e.g. a different exit code or content hash), which surfaces substitution attacks.

A trajectory is **faithful** only when every entry corroborates and nothing is unrecorded.

Matching (`pkg/matching`) is greedy closest-timestamp, one-to-one within a configurable time window, and normalizes command paths so a bare command name (`ls`) corroborates an absolute execve path (`/usr/bin/ls`) by basename.

Verification is built up in tiers of increasing probe coverage:

- **Tier 0** — core data model, matching, and verification logic, exercised with synthetic trajectories and ground truth.
- **Tier 1** — filesystem probe (`pkg/probe/fs`, via `fanotify`).
- **Tier 2** — process probe (`pkg/probe/proc`, via an in-kernel eBPF program on `execve`/`exit_group`/`sched_process_exit`), capturing exec argv, exit codes, and in-kernel timestamps.

Tiers 3-6 (network probes, content hashing, and attack simulation) are planned but not yet implemented.

## Architecture

```
pkg/models        Shared types: TrajectoryEntry, GroundTruthEvent, ActionType
pkg/matching      Action matching rules, including command-path normalization
pkg/verification  Trajectory-vs-ground-truth comparison and verdict classification
pkg/probe/fs      Tier 1 filesystem observer (fanotify)
pkg/probe/proc    Tier 2 process observer (eBPF: execve, exit_group, sched_process_exit)
cmd/simagent      Simulated agent that performs real filesystem/process actions and
                  emits a matching trajectory, for exercising the probes end to end
tests/e2e         End-to-end scenarios wiring simagent + probes + verification together
```

## Requirements

- Go 1.25+
- Linux with eBPF support (Tier 2 probe and its tests)
- `clang` and kernel headers, for regenerating the eBPF bytecode (`bpf2go`)
- Root privileges, for running the fs/proc probes and their tests (they use `fanotify` and load eBPF programs)

## Build & test

```sh
go build ./...

# Regenerate eBPF Go bindings after editing pkg/probe/proc/proc.bpf.c
go generate ./pkg/probe/proc/...

# Run tests
go test ./...
```

Without root, the filesystem, process, and end-to-end tests skip rather than fail, so an unprivileged `go test ./...` run is not a full signal. Run the suite as root to actually exercise the probes:

```sh
sudo go test -v ./...
```

## Project status

This is a research prototype under active development. Tiers 0-2 are implemented and tested; Tiers 3-6 are not yet built. There is no standalone verifier CLI yet — the pipeline (simulated agent, probes, and verification) is currently exercised through the end-to-end tests in `tests/e2e` and the `simagent` binary in `cmd/simagent`.
