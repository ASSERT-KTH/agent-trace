# Agent-Trace: Trajectory Faithfulness Verifier

[![Tests](https://github.com/ASSERT-KTH/agent-trace/actions/workflows/test.yml/badge.svg)](https://github.com/ASSERT-KTH/agent-trace/actions/workflows/test.yml)

AI agents self-report their actions through trajectories. But what if the agent is compromised, hallucinating, or actively hiding malicious actions? 

**Agent-Trace** is a verification engine that assesses the *faithfulness* of AI agent trajectories by cross-referencing their self-reported logs against independent, host-level OS probes.

