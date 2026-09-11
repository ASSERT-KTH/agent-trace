
**[Counter-Swarm Doctrine: Containing Coordinated Agent Intrusions](https://arxiv.org/abs/2609.06140)**
 — 2026-09-09

- Gregory N Frank

-
*Abstract:* arXiv:2609.06140v1 Announce Type: new Abstract: Agents can turn shared infrastructure into a channel for coordinated intrusion. The Hugging Face incident
 and a separate public-wiki investigation show why a security assessment may need evidence from several executions and the artifacts they leave behind. We argue that the operational unit of defence should be a revisable coordination episode linking observed
 transfers, task authority, and response history. The central research problem is prospective episode discovery: finding which actions belong together before an evaluator supplies their membership. We define unsanctioned coordination relative to collaboration
 and delegated-authority policy, connect storage-mediated coordination to stigmergy, and specify the evidence needed to distinguish influence from common causes. First-contact signals are one possible input to discovery; the design also follows inherited state
 and later use. A proposed evaluation compares isolated actions, rolling windows, known groups, and prospectively discovered episodes at matched review cost and false-alert workload. It measures harmful outcomes across all assigned population runs and tests
 recurrence after channel closure and state quarantine. A checksum-verified reconstruction of the public wiki export separates the decline in retained writes from later administrative cleanup. The contribution is an incident-grounded position, descriptive analysis,
 and evaluation design. It makes the recommendation to monitor across executions testable without claiming a new detector or a measured containment benefit.




- 
**[ClaimReceipt: Verifying Evidence Sufficiency and Coverage in Agent Evaluations](https://arxiv.org/abs/2609.01992v1)**
 — 2026-09-02

- Peiying Zhu, Sidi Chang


- 
*Abstract:* Agent evaluations face two distinct evidentiary questions: whether a reported claim is recomputable from retained evidence (sufficiency), and whether the retained records cover the committed experiment set (coverage). Generic logs and hash-linked
 transcripts answer neither reliably. We introduce ClaimReceipt, a claim-relative receipt specification and selective verifier that binds typed transaction evidence to a signed experiment manifest and returns PASS, INVALID, or INCONCLUSIVE per claim. We freeze
 the specification before implementation (SHA-256 18d109...b81). On 1,392 historical buyer--seller records, a CR-2 verifier reproduces all five manually labeled audit verdicts, exactly replays 600 deterministic and 792 post-generation records, makes every one
 of 13 declared field groups non-redundant under tested ablations, and returns the expected result on 11/11 semantic faults with 0/8 false positives. We then run a separate prospective CR-3 epoch: 30 assignments are committed before inference, terminal receipts
 are signed and chained, and private evidence is encrypted for an auditor. Complete evidence yields coverage and accounting PASS; withholding one terminal receipt returns INCONCLUSIVE_COVERAGE, while withholding all private openings preserves coverage and protocol
 verification but makes economic claims inconclusive, exactly matching a preregistered prediction. Receipt instrumentation adds 0.021% of model-inference time and 9.9 KB per transaction. A specification-legibility probe indicates that our own frozen specification
 is not yet unambiguous to an independent reader. Claim verification therefore requires both claim-sufficient evidence and a committed universe against which omissions become visible.



