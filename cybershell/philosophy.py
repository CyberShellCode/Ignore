
# Auto-generated: embedded philosophies & constraints (single-file source).

def get_core_design_philosophies() -> str:
    """Return the embedded Core Design Philosophies and Constraints as Markdown."""
    return r"""# CyberShell Core Design Philosophies

1) **Lab-safe core, operator-extended edge.**
   The kernel never performs live exploitation, scanning, or exfiltration. Real-world actions live in user plugins that you run with authorization.

2) **Explainable planning.**
   Plans are produced from observable signals (mapper), mined documentation (local-only), optional LLM suggestions, and ODS pivots. Every step records its rationale.

3) **Continuous, operator-controlled learning.**
   You control what the system learns (training data, HITL feedback, corpora). Models can be updated offline and hot-swapped into the runtime.

4) **Composability and auditability.**
   Everything is a small component with typed inputs/outputs. Reports are deterministic Markdown with an ordered log of steps and results.

5) **Deterministic defaults, opt-in autonomy.**
   No background web access, dependency installs, or system modifications. Any autonomy extensions (e.g., retries, headless browser, tooling) are explicit in your plugins.

6) **Scaffold for proof—not proof by itself.**
   The core focuses on hypothesis generation, research, and orchestration. Impactful PoCs require your authorized evidence-collection plugins.

---

## Architectural, Evidence, and Operational Constraints

### A. Core architecture constraints
- **No first-party PoC generation.** Without your action plugins, CyberShell cannot produce repro steps, request traces, or artifacts that many programs require.
- **Mapper quality = training quality.** The classifier is TF-IDF + linear OvR; it’s fast and online-friendly but not SOTA. Poor labels or domain drift → weaker family mapping.
- **Document Miner is lightweight.** TF-IDF + simple extractive summaries. It won’t perform semantic reasoning over complex PDFs/diagrams or codebases.
- **ODS depends on signal quality.** If your plugins don’t emit reliable `evidence_score` (0–1) or clear signals, ODS pivots may be suboptimal or stall early.
- **No browser automation built-in.** No headless browser/DOM driving, CSP/report-only parsing, or visual diffing out of the box.
- **No auth/session orchestration in core.** Handling multi-step auth, MFA, OAuth device codes, SSO, or mobile-app flows requires your plugins.
- **No WAF/anti-automation strategy.** Rate limits, IP reputation, captchas, anomaly detection—none are handled in the kernel.
- **No target inventory/discovery.** There’s no crawler/sitemap/JS-route analyzer. Target enumeration must be implemented by you.
- **No taint/dataflow or code-level analysis.** The system doesn’t parse source, bytecode, or ASTs; it only consumes the text you feed (signals, docs).
- **No concurrency orchestration.** The kernel doesn’t schedule distributed scans or race attempts; plugins must implement any parallelism safely.

### B. Evidence & reporting constraints
- **Limited artifact pipeline.** The default report is markdown-text; there’s no automatic HAR capture, packet traces, screenshotting, or PCAP/heap dumps without plugins.
- **No standardized PoC bundles.** There’s no built-in packaging of “replayable PoC” (scripts + config + sanitized inputs + evidence). You must add this.
- **No chain-of-custody guarantees.** Timestamps/log integrity, hashing of artifacts, and reproducibility metadata are not enforced by default.

### C. Operational constraints
- **Scope management is minimal.** A basic in-scope check exists; there’s no per-program rules engine, rate caps, or asset registry sync.
- **No auto-throttling or safe-mode fallback.** The kernel won’t slow down automatically based on target health/5xx rates unless your plugins do.
- **Air-gapped by design.** Without a custom connector, it won’t fetch external docs, CVEs, or advisories during a run."""
