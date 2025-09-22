# prompts_appendix_A.py

PROMPT_A1 = """\
Prompt A.1 — Threat Instance Disentanglement

Role: Senior CTI analyst. Separate entangled threats in a raw report into distinct, audit-ready instances; 
ground all fields with evidence.

Input: Raw CTI text (advisory/blog/ticket), optional seeds (vendor/product family, IOCs), observed timestamps.

Output (JSON array, per instance):
- threat_id, cve_ids
- affected: {vendor, product, version(s), component(s)}
- classifiers: {candidate CWE(s), ATT&CK tactic/technique ids (optional)}
- timeline: {disclosure, PoC, weaponization, in_the_wild} (ISO date or null)
- artifacts: IOCs {urls, hashes, ips}, relevant repo or PoC links
- evidence: [{verbatim_span, source_pointer, confidence}]
- related_to: cross-instance relations

Constraints:
- Do not fabricate unknowns; return null and justify with evidence.
- Split when vendor/product, exploitation path, or impact differs.
- Require at least one evidence span per instance.
"""

PROMPT_A2 = """\
Prompt A.2 — Canonical Mapping & Conflict Resolution

Role: Mapping specialist. For each instance, produce canonical links and normalized labels with explicit evidence grounding.

Tasks:
1) Registry linking: NVD, KEV, and vendor advisories with permalinks.
2) Taxonomy mapping: CWE and ATT&CK with confidence (high/med/low).
3) Exploit status: one of {not_public, poc_available, weaponized, in_the_wild}.
4) Conflict policy priority: vendor advisory > CVE/NVD > reputable research blog > aggregation.

Output (per instance) JSON:
{
  "links": {...},
  "cwe": [...],
  "attck": [...],
  "exploit_status": "...",
  "justification": "...",
  "citations": [...]
}
"""

PROMPT_A3 = """\
Prompt A.3 — CVSS v3.1 Metric Assignment (Span-Grounded)

Role: CVSS classifier. Assign base metrics AV, AC, PR, UI, S, C, I, A with concise rationales and quoted evidence.

Procedure:
1) For each metric, produce: {label, rationale, evidence_span}.
2) If evidence is absent or contradictory, set label="uncertain" and needs_review=true.
3) Emit a base-score recommendation only if all metrics are non-uncertain.

Expected JSON example:
{
  "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
  "rationales": { "AV": "...", "AC": "...", "...": "..." },
  "evidence_spans": { "AV": "...", "AC": "...", "...": "..." },
  "needs_review": false
}
"""

PROMPT_A4 = """\
Prompt A.4 — Mitigation & Detection Retrieval

Role: Remediation researcher. Retrieve patches, workarounds, detections, and monitoring guidance from authoritative sources.

Source priority (descending):
- Vendor advisories
- CISA KEV notes
- NVD references
- Maintainer repositories
- Reputable CERT/blogs

Return a JSON bundle:
{
  "patches": [
    { "version_constraints": "...", "steps": "...", "regressions": "..." }
  ],
  "workarounds": [
    { "config_changes": "...", "segmentation_or_acl": "...", "isolation": "..." }
  ],
  "detections": [
    { "siem": "...", "edr_yara_ids": "...", "log_queries": "..." }
  ],
  "provenance": [
    { "url": "...", "snippet": "...", "retrieved_at": "ISO8601" }
  ]
}

Notes:
- Deduplicate semantically equivalent items; prefer most recent and vendor-preferred entries.
- Include retrieval timestamps in ISO8601 format.
"""

PROMPT_A5 = """\
Prompt A.5 — Risk-Aware Mitigation Prioritization

Role: Risk manager. Given threats and candidate actions, output a ranked, implementable plan with justifications.

Scoring:
  Risk_k = s_k * p_k * alpha_exp * beta_crit
  where s_k = static severity (e.g., CVSS base score), 
        p_k = exploitation probability, 
        alpha_exp = exposure factor, 
        beta_crit = asset criticality.

Tie-breakers (apply if |delta_Risk| < 0.1):
1) Patch availability (patch > workaround > none)
2) Implementation complexity (simple > moderate > complex)
3) Exploitation velocity (faster > slower)
4) Business disruption (lower > higher)

Output JSON (array):
[
  { 
    "rank": 1,
    "target": "...",
    "action": "...",
    "ETA": "24h",
    "justification": "...",
    "dependencies": []
  }
]
"""

