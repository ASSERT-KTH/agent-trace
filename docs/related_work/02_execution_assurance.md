## 2. Execution evidence and assurance

These systems verify that a trajectory faithfully reflects what happened, or provide cryptographic evidence binding trajectory entries to real events.

---

### Reproducible Coding Agent Trajectories

*Monperrus, Jul 2026* · tool · `TM-A`
[blog post](https://www.monperrus.net/martin/reproducible-agent-trajectory) · [GitHub](https://github.com/ASSERT-KTH/reproducible-trajectories)

Defines execution-reproducibility for coding-agent trajectories via two verification criteria.
The *edit criterion* replays file edits from a known git parent commit and checks that the resulting file states exactly match the committed files.
The *command criterion* re-executes shell commands and checks that stdout/stderr are byte-identical to what was recorded.
Implemented as a Python package (~120 lines) in the `reproducible-trajectories` repository.

The trust anchor is the git repository.
The edit criterion uses commit history as ground truth for file state.
The command criterion uses deterministic re-execution as ground truth for command output.

> **Scope and stated constraints.**
> Scoped to coding agents that operate within a git repository.
> The edit criterion requires git-tracked files; file operations outside the repository (e.g., reading `/etc/passwd`, writing to `/tmp`) are not covered.
> The command criterion requires deterministic commands; non-deterministic commands (API calls, time-dependent output) fail verification even when faithfully recorded.
> No paper formalizes the concept; it exists as a tool and a blog post.

---

### halo-record

*Kuan, Aug 2026* · tool · `TM-A` `TM-C`
[GitHub](https://github.com/bkuan001/halo-record) · [Help Net Security interview](https://www.helpnetsecurity.com/2026/08/31/halo-record-open-source-ai-agent-audit-trail/)

An append-only, hash-chained JSONL log for agent actions.
Each record contains the hash of the previous record, forming a tamper-evident chain.
External witnesses (remote services) periodically store the chain's record count and head hash.
If the chain is later truncated or rewritten from a point, the witness's stored state reveals the discrepancy.

> **Author-acknowledged limitations.**
> The project documentation explicitly states: "A self-held chain proves integrity: nothing was edited or reordered after the fact. It cannot prove completeness."
> The witness detects chain truncation (removing entries from the tail) but does not detect selective omission within the chain if the chain is re-sealed after dropping entries from the middle.
> The agent itself writes the chain, so fabricated entries hash correctly and are indistinguishable from real ones within the chain structure.

---

### Sello: Receiver-Attested Confidential Receipts for AI Agent Actions

*Figuera et al., Jun 2026* · paper (22 pp.) · `TM-B`
[arXiv 2606.04193](https://arxiv.org/abs/2606.04193)

The Sello protocol addresses the problem of agents or their operators controlling their own activity logs.
It moves the trust boundary to the service receiving the agent's request.
The protocol works in four steps: the agent sends a request to a service; the service signs a receipt describing the action it observed; the receipt is encrypted to the agent owner via HPKE (so the agent and operator cannot read or suppress it in transit); and the receipt is published to a witness-cosigned transparency log.

The paper defines four security properties:

| Property | Definition |
|:---------|:-----------|
| P1 (Completeness) | If an agent contacts a participating service, the owner will eventually learn about it via a receipt |
| P2 (Confidentiality) | Only the owner can read receipt contents |
| P3 (Non-repudiation) | Once published, neither the service nor the agent can deny the interaction |
| P4 (Integrity) | The receipt accurately reflects what the service observed |

The paper includes a comparison table evaluating seven other receipt-based protocols (Signet, Agent Receipts, AgentBound, Pipelock, Openterms, and others) against these four properties.
Sello is the only protocol in the comparison that achieves all four simultaneously, primarily because it places the signing authority at the receiver rather than the operator or agent.

> **Author-acknowledged limitations (from the paper's discussion).**
>
> *Suppression attack:* The agent contacts a service and obtains a receipt, but suppresses it before it reaches the transparency log.
> The paper notes this is partially mitigated by the service's own publication of the receipt, but requires the service to independently publish.
> If the service only responds to the agent and does not independently publish, suppression is possible.
>
> *Service collusion:* If the receiving service colludes with the agent, the service can sign a false receipt or refuse to sign a true one.
> The protocol does not protect against collusion between the agent and the receiver.
>
> *Adoption-incentive problem:* Sello requires services to implement the receipt protocol.
> The paper acknowledges that services have no inherent incentive to do so, creating a deployment barrier.
> Coverage is limited to participating services.
>
> *Local actions:* Actions that do not involve an external service (file reads, computation, internal reasoning) have no receiver to sign a receipt.
> These actions are outside Sello's coverage by design.

---

### TRACE: Trajectory Attribution via Watermarking

*Gao et al., Jul 2026* · paper · `TM-C`
[arXiv 2607.08400](https://arxiv.org/abs/2607.08400)

Embeds attribution watermarks into agent trajectory logs.
The watermarks survive deletion, rewriting, and re-ordering of entries.
The purpose is to answer "whose agent produced this trajectory" for accountability and IP protection.

> **Stated scope.**
> Addresses attribution (provenance of the trajectory document), not faithfulness (whether the trajectory reflects what actually happened).
> A compromised runtime that controls the recording process can embed a valid watermark into a fabricated trajectory.
> The watermark authenticates the trajectory's origin, not its content.

---

### Signet

*Hou, 2025-2026* · tool · `TM-B` `TM-C`
[GitHub](https://github.com/Prismer-AI/signet)

MCP-focused middleware that produces cryptographically signed records of agent tool calls.
Supports two signing modes: operator-side signing (the operator's infrastructure signs the receipt) and bilateral co-signing (both the operator and the MCP server sign).
Co-signing provides stronger guarantees because the server independently attests to the interaction.

> **Stated scope and constraints.**
> Bilateral co-signing requires the MCP server to be instrumented with Signet.
> Without server co-signing, the operator alone signs, placing the trust boundary at the operator.
> An operator who controls the signing key can fabricate signed receipts.
> The Sello paper's comparison table (Section 2.2) identifies this as the operator-side trust boundary limitation shared by several receipt protocols.

---

### Agent Receipts

*Jongerius, 2025-2026* · tool/spec · `TM-C`
[agentreceipts.ai](https://agentreceipts.ai/)

Operator-side signing of agent actions via W3C Verifiable Credentials.
Each action produces a signed receipt that can be independently verified.
Designed for compliance and audit trails.

> **Stated constraints.**
> The operator signs.
> If the operator is the adversary (TM-C threat model), the operator can fabricate signed receipts.
> The Sello paper's analysis places Agent Receipts in the operator-side trust class, noting it does not achieve receiver-side attestation.

---

### Proof of Execution

*Rhodes & Kang, Apr 2026* · paper · `TM-C`
[arXiv 2607.05397](https://arxiv.org/abs/2607.05397)

Formalizes agent execution as a proof-carrying object.
Defines a Contract (pre/post-conditions), an Execution Certification Evidence Set (ECES), and a Replay Context.
The framework specifies five invariants that a valid proof must satisfy:

| Invariant | What it checks |
|:----------|:---------------|
| I1 (Plan consistency) | Execution follows the declared plan |
| I2 (Precondition satisfaction) | Each step's preconditions are met |
| I3 (Sequential validity) | Steps execute in declared order |
| I4 (Post-condition verification) | Each step's post-conditions hold after execution |
| I5a/I5b (Deterministic replay) | Re-execution produces the same result |

The Prime Execution Model separates four concerns: planning (what to do), enforcement (checking authorization), effect (executing the action), and recording (logging the result).
The paper provides a soundness proof: if all invariants hold, the proof correctly represents the execution.

> **Author-stated assumptions and scope.**
>
> *Assumption A4 (Recorder integrity):* The recording component is assumed to be honest.
> The paper states that recorder compromise is a deployment concern, not an in-scope threat.
> If the recorder is compromised, it can fabricate valid-looking proof objects.
>
> *Assumption A5 (Trace completeness, ε_tc):* The paper treats trace completeness as a deployment assumption, not a verified property.
> The completeness parameter ε_tc represents the fraction of execution events successfully captured.
> The paper acknowledges that achieving ε_tc = 1 (perfect completeness) depends on the deployment environment.
>
> *Planner compromise:* The paper explicitly states: "Planner compromise is out of scope."
> If the planning component is compromised, it may generate a plan that appears valid but serves adversarial goals.
> The proof system verifies that the execution matches the plan, not that the plan is benign.

---
