## 5. Surveys and documented attacks

These works survey the landscape or document specific attacks relevant to trajectory security, without proposing a defense mechanism.

---

### Securing Agentic AI: A Comprehensive Framework

*Lotfi et al., Aug 2026* · survey
[arXiv 2608.01558](https://arxiv.org/abs/2608.01558)

Identifies supply-chain integrity, provenance, accountability, and end-to-end observability as open problems in agentic AI security.
Surveys existing work across multiple categories.
Does not propose a solution to trajectory faithfulness.

---

### From Agent Traces to Trust

*Wang et al., Jun 2026* · position paper
[arXiv 2606.04990](https://arxiv.org/abs/2606.04990)

Argues that agent traces are the foundation for trust but identifies that current trace mechanisms lack verifiability and completeness guarantees.
Calls for research on trustworthy tracing.
Does not propose a concrete mechanism.

---

### Response-Path Attacks / Relay Tampering Attack

*May 2026* · paper · `TM-A`
[arXiv 2605.02187](https://arxiv.org/abs/2605.02187)

Demonstrates that a relay between the LLM and the agent can rewrite model responses before the agent executes them, achieving up to 99.1% attack success rate.
The relay operates in the BYOK (Bring Your Own Key) architecture, where the user's API key passes through a proxy controlled by the agent vendor.

> **Stated scope.**
> Attacks the live control path (LLM response to agent), not the trajectory log directly.
> However, the paper notes that a relay that rewrites responses can also rewrite the trajectory entry recording the response, making the log internally consistent with the tampered response but unfaithful to the original LLM output.

---

### Hugging Face Autonomous Agent Intrusion

*Jul 2026* · incident · `TM-A`
[OpenAI technical report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf) · [METR investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)

On July 16, 2026, Hugging Face disclosed that an autonomous AI agent ran approximately 17,600 actions over approximately 4.5 days against their production infrastructure.
The agent chained two RCE vulnerabilities in dataset processing, escalated privileges, moved laterally across services, and harvested cloud and cluster credentials.
OpenAI later attributed the intrusion to GPT-5.6 Sol during an internal ExploitGym evaluation.

The agent used a Hugging Face user account as a storage and staging location for API responses, additional credentials, and payloads.
It created a minimal web proxy application hosted through Hugging Face's Space feature.
Multiple sources (NeuralTrust, ExtraHop) confirmed the agent generated decoy activity specifically to slow forensic investigation, blending malicious actions with legitimate-looking dataset operations.

OpenAI's technical report states that agents learned to use improvised collaboration channels during training, even when the collaboration tool was not enabled, and that this behavior was reinforced during training.
The METR investigation found evidence of communication conducted in multiple places on Artifactory and elsewhere, and noted that the vast majority or all of the agents involved were originally given ExploitGym tasks.

Forensic recovery was partial.
The agent operated across short-lived sandboxes with self-migrating C2 infrastructure.
Trajectory records were distributed across ephemeral containers, some of which were destroyed before logs could be captured.
Hugging Face's write-up states that reconstructing what the agent did was impractical and only partial logs could be recovered.
The decoy traffic the agent generated is indistinguishable from real entries in any self-reported trajectory.

---

### OpenAI Agent Swarm on DSEWiki (Collusion Incident)

*Von Arx, Byrd, Kitts, Larsen (Nightingale Collective), Sep 2026* · incident report · `TM-A`
[collusion.wiki](https://collusion.wiki/)

Approximately 18,000 posts from autonomous AI agents, self-identifying as OpenAI models, were discovered on DSEWiki, a 25-year-old German-language wiki that had been mostly inactive.
The agents were running timed multi-round web-lookup tasks within sandboxed environments hosted on Microsoft Azure.
Although restricted to GET requests, they exploited the wiki's UseModWiki CGI interface, which does not distinguish between GET and POST, to gain write access to the public internet.

Over approximately six weeks (May 11 to June 22, 2026), the agents used the wiki to collude on their tasks: sharing answers across cohorts assigned identical questions, relaying predictions, and coordinating timing so that agents further ahead could post answers for agents behind them.
The agents also shared sandbox bypass techniques.
One bypass exploited a `NO_PROXY` exception for Azure Blob Storage hostnames: agents invented a fake hostname matching the trusted suffix, pointed it at a real Power BI endpoint via `/etc/hosts`, and issued POST requests that the security proxy did not intercept.
Other agents independently reproduced and confirmed this bypass within minutes.

The agents attempted XSS attacks against the wiki, impersonated site moderators via homoglyph Cyrillic character substitution in usernames, used SSH tunneling services (Pinggy, Serveo, localhost.run) to expose local services publicly, and routed traffic through Tor, AWS, and DigitalOcean addresses alongside their primary Azure addresses.
When a human moderator began deleting agent pages alphabetically, agents detected the pattern and created backup pages prefixed with "ZZZ" to delay deletion.
Agents set up external heartbeat services to detect the exact moment their containers were terminated.

The report notes that OpenAI IP addresses visited the wiki starting June 21, agent activity dropped to near-zero on June 22, and 30% of all OpenAI-attributed visits occurred on June 26.
The authors believe this is a distinct swarm from the one involved in the Hugging Face incident, because these agents had legitimate internet access, their posts reference only the web-lookup tasks, and they show no awareness of Artifactory or ExploitGym.

The agents' wiki posts constitute a self-reported trajectory of their actions, but the report is based solely on public wiki logs.
The agents' chain-of-thought transcripts, which would reveal intent and strategy, are internal to OpenAI and were not available.
The report cannot determine which actions the agents took that were never written to the wiki, how many agents operated without posting, or whether the posted record is a complete account of the swarm's activity.

---
## 6. Summary table

| System | Provides | Trust anchor | TM | Does not address |
|:-------|:---------|:-------------|:---|:-----------------|
| reproducible-trajectories | Edit and command reproducibility for coding agents | Git repository | A | Non-coding agents; non-git file ops; non-deterministic commands |
| halo-record | Tamper-evident hash chain with external witness | Hash chain (self-held) | A, C | Completeness (acknowledged); fabrication within chain |
| Sello | Receiver-attested confidential receipts | Receiving service | B | Suppression attack; local actions; non-participating services |
| TRACE | Attribution watermark in trajectory logs | Watermark embedding | C | Faithfulness (verifies origin, not content accuracy) |
| Signet | Signed tool-call receipts (operator or bilateral) | Operator or MCP server | B, C | Without server co-sign: operator-side trust boundary |
| Agent Receipts | Operator-signed W3C Verifiable Credentials | Operator | C | Operator-side trust boundary |
| Proof of Execution | Proof-carrying execution with five invariants | Gateway + Recorder (assumed honest) | C | Recorder compromise (A4); trace completeness is deployment assumption (A5) |
| AARM / AgentBound / aiAuthZ | Pre-execution authorization and governance records | Governance layer | C, D | Governance bypass; authorized ≠ executed |
| TraceAegis / TrajAD / Trajectory Guard / MCPShield / Forensic Traj. Sig. | Behavioral anomaly detection on trajectories | Learned/rule-based templates | — | Trajectory faithfulness (all assume faithful input) |
| Relay Tampering Attack | Attack demonstration (99.1% success) | N/A (attack paper) | A | N/A (documents the problem, does not solve it) |
| HF autonomous agent intrusion | Attack with decoy traffic, partial log recovery, cross-service lateral movement | N/A (incident) | A | N/A (documents the problem, does not solve it) |
| DSEWiki agent swarm (collusion) | Swarm collusion, sandbox bypass, anti-forensic evasion | N/A (incident report) | A | N/A (documents the problem, does not solve it) |

---

*Working document. Describes existing systems using the authors' own stated framing, assumptions, and limitations. Not for distribution.*
