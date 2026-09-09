## 4. Behavioral anomaly detection

These systems analyze trajectory content to detect anomalous, malicious, or unsafe action sequences.
They operate on the trajectory as input and flag deviations from expected behavior patterns.

All systems in this category share a common stated assumption: the trajectory faithfully records what the agent did.
They operate on trajectory content, not on independent observations.
If the trajectory is manipulated to remove or disguise the malicious actions, the detector processes the manipulated version.

---

### TraceAegis

*Oct 2025* · paper
[arXiv 2510.11203](https://arxiv.org/abs/2510.11203)

Learns normal trajectory patterns and flags deviations.
Uses trajectory traces as training data to build behavioral profiles of agents, then detects anomalous action sequences at runtime.

---

### TrajAD

*Feb 2026* · paper
[arXiv 2602.06443](https://arxiv.org/abs/2602.06443)

ML-based anomaly detection on agent trajectories.
Trains on trajectory datasets to distinguish normal from abnormal action sequences.
Cannot distinguish a faithful trajectory containing anomalous behavior from an unfaithful trajectory crafted to appear normal.

---

### Trajectory Guard

*Jan 2026* · paper
[arXiv 2601.00516](https://arxiv.org/abs/2601.00516)

Rule-based and ML-based trajectory analysis for detecting unsafe agent behavior.
Combines predefined rules with learned patterns.

---

### MCPShield

*May 2026* · paper
[arXiv 2605.11053](https://arxiv.org/abs/2605.11053)

Monitors MCP tool calls and applies safety filters.
Detects potentially dangerous tool invocations based on predefined criteria and behavioral patterns.
Operates on the tool call as observed by the MCP middleware, not on independent host-level observations.

---

### Forensic Trajectory Signatures

*Jun 2026* · paper
[arXiv 2606.30566](https://arxiv.org/abs/2606.30566)

Defines behavioral signatures for forensic analysis of agent trajectories.
Identifies patterns that indicate specific attack types or policy violations.
Forensic signatures match trajectory content, not independently verified events.

---
