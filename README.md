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
- **Tier 4 (in progress)** — filesystem content verification: SHA-256 of a file's final contents is recorded at `FAN_CLOSE_WRITE`.

Tier 3 (network), remaining Tier 4 evidence capture, Tier 5 (attack simulation), and Tier 6 (real-agent integration) are planned.

## Architecture

```
pkg/models        Shared types: TrajectoryEntry, GroundTruthEvent, ActionType
pkg/content       Shared SHA-256 content-digest helpers
pkg/matching      Action matching rules, including command-path normalization
pkg/verification  Trajectory-vs-ground-truth comparison and verdict classification
pkg/probe         Observer interface every probe implements (used by cmd/watch)
pkg/probe/fs      Tier 1 filesystem observer (fanotify)
pkg/probe/proc    Tier 2 process observer (eBPF: execve, exit_group, sched_process_exit)
cmd/simagent      Simulated agent that performs real filesystem/process actions and
                  emits a matching trajectory, for exercising the probes end to end
cmd/watch         Ground-truth recorder CLI: runs the requested probes live, prints
                  events as they're captured, writes ground truth JSON on exit
cmd/verify        Verification-engine CLI: compares a trajectory and a ground truth
                  JSON and prints the FAITHFUL / NOT FAITHFUL verdict
tests/e2e         End-to-end scenarios wiring simagent + probes + verification together
```

`cmd/watch`, `cmd/simagent`, and `cmd/verify` map directly onto the three components in the architecture design (`docs/plan/01_protocol_architecture.md`): ground-truth recorder, the thing being observed, and verification engine + reporting layer.

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

## Live demo

Beyond the automated tests, `watch` + `simagent` + `verify` let you run every implemented tier interactively across two terminals — a probe watching live in one, a simulated agent acting in the other — instead of only reading assertions in test output. Build all three first:

```sh
go build -o watch    ./cmd/watch
go build -o simagent ./cmd/simagent
go build -o verify   ./cmd/verify
```

**Terminal A** — start the ground-truth recorder on a scratch workspace (requires root: fanotify + eBPF):

```sh
mkdir -p /tmp/agent-trace-demo
sudo ./watch --workspace /tmp/agent-trace-demo --proc-filter wc --out ground_truth.json
```

It prints each file and process event as it's captured. `--proc-filter wc` scopes the process probe to the `wc` command `simagent` runs below, so unrelated processes on the machine don't pollute the ground truth.

**Terminal B** — run the simulated agent against the same workspace:

```sh
./simagent --workspace /tmp/agent-trace-demo --trajectory-out trajectory.json
```

It writes a file, renames it, runs `wc -l` on it, then deletes it — exercising the Tier 1 filesystem probe, the Tier 2 process probe, and the mixed file+process verification together.

Back in **terminal A**, press Ctrl+C once `simagent` finishes. `watch` writes `ground_truth.json` and exits. Then, in either terminal:

```sh
./verify --trajectory trajectory.json --ground-truth ground_truth.json
```

This prints a FAITHFUL verdict with a per-category breakdown. To see the NOT FAITHFUL path, rerun `simagent` with `--drop-entry 0` (or any valid index) to omit a self-reported action before it's written out, then `verify` again — `Unrecorded` will be non-empty and the verdict flips.

This harness is meant to grow with the project: `pkg/probe.Observer` is the interface every probe implements, and `cmd/watch`'s `probeBuilders` map is a single-entry extension point, so adding Tier 3's network probe (once it exists) means adding one build function, not a new tool.

## Project status

This is a research prototype under active development. Tiers 0-2 are implemented and tested; Tiers 3-6 are not yet built.
