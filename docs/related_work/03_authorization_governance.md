## 3. Runtime authorization and governance

These systems enforce policies on agent actions before execution and record governance decisions.
They focus on authorization (should this action be allowed?) rather than trajectory verification (did this action actually occur as recorded?).

---

### AARM (Autonomous Agent Runtime Management)

*CSA, Feb 2026* · specification · `TM-C` `TM-D`
[arXiv 2602.09433](https://arxiv.org/abs/2602.09433)

A Cloud Security Alliance specification for managing autonomous agent runtimes.
Defines what a compliant runtime must do: intercept actions before execution, evaluate them against policy, enforce authorization decisions, and produce signed governance records.
Focuses on the runtime management plane rather than trajectory verification.

> **Stated scope.**
> AARM records governance decisions, not the actual actions the agent executed.
> An authorized action may differ from the executed action if the runtime is bypassed.
> The specification does not address supply-chain compromise of the runtime itself or relay attacks below the governance layer.

---

### AgentBound

*Jun 2026* · paper · `TM-C` `TM-D`
[arXiv 2606.30970](https://arxiv.org/abs/2606.30970)

Pre-execution enforcement layer for agent actions.
Intercepts tool calls, evaluates them against a declarative policy, and produces cryptographically signed records of enforcement decisions.

> **Stated constraints.**
> Records enforcement decisions (allow/block), not ground-truth observations of what was executed.
> If the enforcement layer is bypassed (via supply-chain compromise of the agent runtime, or a relay below the enforcement point), actions execute without enforcement records and no mechanism detects the gap.
> The Sello comparison table evaluates AgentBound as lacking receiver-side attestation.

---

### aiAuthZ

*Jul 2026* · paper · `TM-C`
[arXiv 2607.05518](https://arxiv.org/abs/2607.05518)

An authorization framework for AI agent actions.
Defines a policy language and evaluation engine for deciding whether an agent action should be permitted.
Produces authorization audit records.

> **Stated scope.**
> Authorization, not verification.
> Governs what the agent is allowed to do, not what it actually did.
> No mechanism verifies that the authorized action is the action that was executed.

---
