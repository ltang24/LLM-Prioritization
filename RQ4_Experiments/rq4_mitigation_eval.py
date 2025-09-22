#!/usr/bin/env python3
"""
POLAR RQ4: Mitigation Recommendation Efficacy Evaluation (with g4f)
Evaluates mitigation retrieval and prioritization capabilities using g4f LLM backend
"""

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
import g4f


# ==============================
# Data Structures
# ==============================
@dataclass
class ThreatInstance:
    threat_id: str
    cve_id: Optional[str]
    vendor: str
    product: str
    versions: List[str]
    static_severity: float
    exploitation_prob: float
    exposure_factor: float
    asset_criticality: float


@dataclass
class MitigationAction:
    action_id: str
    action_type: str
    description: str
    target_threat: str
    implementation_complexity: str
    business_impact: str
    effectiveness: float
    source: str
    url: Optional[str]
    prerequisites: List[str]


# ==============================
# LLM Wrapper
# ==============================
class LLMClient:
    def __init__(self, model: str = "gpt-4o"):
        self.model = model

    def generate(self, prompt: str, temperature: float = 0.0) -> str:
        """Send prompt to g4f backend"""
        return g4f.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
        )


# ==============================
# Evaluator
# ==============================
class MitigationRecommendationEvaluator:
    def __init__(self, llm_client: LLMClient, knowledge_sources: Dict[str, str]):
        self.llm_client = llm_client
        self.knowledge_sources = knowledge_sources

    def _build_prompt(self, threat: ThreatInstance) -> str:
        return f"""
System role: You are a remediation researcher. Retrieve patches, workarounds, detections, and
monitoring guidance from authoritative sources for the given threat.

Threat Instance:
- CVE ID: {threat.cve_id}
- Vendor: {threat.vendor}
- Product: {threat.product}
- Versions: {threat.versions}
- Static Severity: {threat.static_severity}
- Exploitation Probability: {threat.exploitation_prob}

Source Priority: Vendor advisories > CISA KEV notes > NVD references > CERT blog posts

Return JSON array with mitigation actions:
{{
  "action_id": "unique_identifier",
  "action_type": "patch|workaround|detection|isolation",
  "description": "specific remediation steps",
  "implementation_complexity": "simple|moderate|complex",
  "business_impact": "low|medium|high", 
  "effectiveness": 0.0-1.0,
  "source": "vendor|cisa_kev|nvd|attack",
  "url": "source_url",
  "prerequisites": ["list", "of", "prerequisites"]
}}
"""

    def _extract_json(self, response: str) -> str:
        """Extract JSON content from LLM response safely"""
        matches = re.findall(r"[\[{].*[\]}]", response, re.DOTALL)
        if matches:
            return matches[0]
        return response.strip()

    def retrieve_mitigations(self, threat: ThreatInstance) -> List[MitigationAction]:
        """Retrieve mitigation actions for a given threat instance"""
        prompt = self._build_prompt(threat)
        try:
            response = self.llm_client.generate(prompt, temperature=0.1)
            json_data = self._extract_json(response)

            try:
                parsed = json.loads(json_data)
            except json.JSONDecodeError:
                print(f"[WARN] JSON parsing failed, raw response: {response[:200]}...")
                return []

            if isinstance(parsed, dict):
                parsed = [parsed]

            actions = []
            for d in parsed:
                actions.append(
                    MitigationAction(
                        action_id=d.get("action_id", ""),
                        action_type=d.get("action_type", "patch"),
                        description=d.get("description", ""),
                        target_threat=threat.threat_id,
                        implementation_complexity=d.get("implementation_complexity", "moderate"),
                        business_impact=d.get("business_impact", "medium"),
                        effectiveness=float(d.get("effectiveness", 0.5)),
                        source=d.get("source", "nvd"),
                        url=d.get("url"),
                        prerequisites=d.get("prerequisites", []),
                    )
                )
            return actions

        except Exception as e:
            print(f"[ERROR] retrieve_mitigations: {e}")
            return []


# ==============================
# Demo Run
# ==============================
if __name__ == "__main__":
    client = LLMClient()
    knowledge_sources = {
        "nvd": "https://nvd.nist.gov/",
        "cisa_kev": "https://cisa.gov/known-exploited-vulnerabilities-catalog",
        "attack": "https://attack.mitre.org/",
        "vendor_advisories": "https://msrc.microsoft.com/"
    }

    evaluator = MitigationRecommendationEvaluator(client, knowledge_sources)

    threat = ThreatInstance(
        threat_id="test_threat",
        cve_id="CVE-2021-34527",
        vendor="Microsoft",
        product="Windows Print Spooler",
        versions=["Windows 10", "Windows 11"],
        static_severity=8.8,
        exploitation_prob=0.85,
        exposure_factor=1.5,
        asset_criticality=2.0,
    )

    actions = evaluator.retrieve_mitigations(threat)
    if actions:
        print(f"Retrieved {len(actions)} mitigation actions:")
        for a in actions:
            print(f"  [+] {a.action_id} | {a.action_type} | {a.source} | {a.description[:60]}...")
    else:
        print("No mitigations retrieved.")
