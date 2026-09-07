# Agent-Trace Repository Guide

This repository contains the Agent Trajectory Faithfulness Verifier, written in Go. Its goal is to provide execution assurance for AI agent trajectories by comparing self-reported actions against ground-truth system probes.

## Codebase Gotchas & Architecture Rules

*   **No Large Autonomous Implementation:** Implementations are done as focused, reviewable units. Tests grow incrementally alongside the implementation.
*   **eBPF Probes:** For Tier 2+, we use `cilium/ebpf` for process probes.
*   **Testing Philosophy:** Every tier MUST have at least one E2E semantic test that demonstrates the requirements. We strongly prefer table-driven `go test` for unit testing.
*   **Module Boundaries:** Keep models (`TrajectoryEntry`, `GroundTruthEvent`, `ActionType`) strictly in `pkg/models`. Do not intermingle matching/verification logic into the data models.

## Documentation Index (Progressive Disclosure)

Do not assume all context is listed here. Search and load the following files when you need context on specific areas:

### Development Plan
*   `docs/plan/01_protocol_architecture.md`: Overall working protocol and design architecture.
*   `docs/plan/02_tiers_0_to_2.md`: Core logic, filesystem probes, and process probes requirements and tests.
*   `docs/plan/03_tiers_3_to_6.md`: Network probes, content hashing, and attack simulation details.

### Related Work & Threat Models
*   `docs/related_work/01_threat_models.md`: The taxonomy of threat models we address.
*   `docs/related_work/02_execution_assurance.md`: Cryptographic evidence and faithful reproduction approaches.
*   `docs/related_work/03_authorization_governance.md`: Pre-execution governance (AARM, AgentBound).
*   `docs/related_work/04_anomaly_detection.md`: TraceAegis, TrajAD, and other detection methods.
*   `docs/related_work/05_surveys_attacks_summary.md`: Documented attacks (e.g., HF intrusion) and summary table.
# SKILL.state Agent Protocol

You are operating under a state-centric execution protocol. Because the user frequently switches agents to manage context limits, you must not rely on conversational history. Instead, you must rely entirely on the explicit structured state persisted in `STATE.md`.

## Execution Loop

For every turn/request you receive, you MUST follow this loop:

1. **Read State:** Your first action should always be to read `STATE.md` to understand the current world state, past progress, and overarching goals.
2. **Execute:** Perform the requested actions or continue the work based on the "Next Steps" outlined in the state.
3. **Update State:** Before ending your turn, you MUST update `STATE.md` (overwriting it or modifying it) to reflect the new state. 

## State Format

The `STATE.md` file should be kept concise and structured. It should ideally contain:
*   **Current Goal:** The overarching objective.
*   **Completed Steps:** What has been accomplished so far (briefly).
*   **Active Context:** Current hypotheses, bugs found, critical files modified, or specific test results.
*   **Next Steps:** The immediate next actions the agent should take on the next turn.

## Golden Rule
**If it's not in `STATE.md`, the next agent won't know about it.** Project all transient reasoning and discoveries into the structured state before you finish!

## Agentic CI & TDD
**Shift Left via Agent Self-Correction:** Before you attempt to commit any code or state that you have finished your turn, you MUST locally run `sudo go test -v ./...` and `go vet ./...` (or `golangci-lint run` if available). Act as your own IDE. Never commit broken code or ignore unhandled errors. If a test or linter fails, fix it immediately.
