# RQ1: Metadata Enrichment Pipeline using g4f
# Description: Given noisy CTI reports, extract structured ThreatInstance(s) and enrich them with metadata (TTPs, CWE)

from dataclasses import dataclass
from typing import List
import os
import json
from tqdm import tqdm
from g4f.client import Client

# -------------------------------
# STEP 1: Define data structures
# -------------------------------
@dataclass
class ThreatInstance:
    threat_id: str
    cve_ids: List[str]
    affected_vendor: str
    affected_product: str
    affected_versions: List[str]
    evidence_spans: List[str]

@dataclass
class EnrichedMetadata:
    threat_id: str
    ttp_mappings: List[str]
    cwe_ids: List[str]

# -------------------------------------
# STEP 2: Load CVE JSONs from folder
# -------------------------------------
def convert_json_to_threat_instance(path):
    with open(path) as f:
        d = json.load(f)
    aff = d.get("Affected", [{}])[0]
    return ThreatInstance(
        threat_id=d.get("CVE Code"),
        cve_ids=[d.get("CVE Code")],
        affected_vendor=aff.get("vendor", "n/a"),
        affected_product=aff.get("product", "n/a"),
        affected_versions=aff.get("versions", []),
        evidence_spans=[d.get("Description", "")]
    )

def load_all_instances(folder):
    all_cases = []
    for root, _, files in os.walk(folder):
        for f in files:
            if f.endswith(".json"):
                all_cases.append(convert_json_to_threat_instance(os.path.join(root, f)))
    return all_cases

# ---------------------------------------------------
# STEP 3: Prompt construction for g4f inference
# ---------------------------------------------------
def build_enrich_prompt(instance: ThreatInstance) -> str:
    return f"""
Given the following threat instance extracted from a CTI report:

- CVE IDs: {instance.cve_ids}
- Affected Product: {instance.affected_product}
- Evidence: {' '.join(instance.evidence_spans)}

Determine the most likely MITRE ATT&CK techniques (TTPs) involved.
Also, extract any relevant CWE IDs.

Respond in the following format:
TTPs: [...]
CWEs: [...]
"""

# ---------------------------------------------------
# STEP 4: LLM Inference with g4f (GPT-4o)
# ---------------------------------------------------
client = Client()

def enrich_metadata(instance: ThreatInstance) -> EnrichedMetadata:
    prompt = build_enrich_prompt(instance)
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    ).choices[0].message.content

    ttp_list, cwe_list = [], []
    for line in response.split("\n"):
        if line.startswith("TTPs"):
            ttp_list = eval(line.split(":", 1)[1].strip())
        elif line.startswith("CWEs"):
            cwe_list = eval(line.split(":", 1)[1].strip())

    return EnrichedMetadata(
        threat_id=instance.threat_id,
        ttp_mappings=ttp_list,
        cwe_ids=cwe_list
    )

# --------------------------------------------
# STEP 5: Main experiment runner for RQ1
# --------------------------------------------
def run_rq1_eval(data_folder="data/extract_meta"):
    all_instances = load_all_instances(data_folder)
    print(f"Loaded {len(all_instances)} threat instances")

    for inst in tqdm(all_instances):
        enriched = enrich_metadata(inst)
        print(f"[{inst.threat_id}] → TTPs: {enriched.ttp_mappings} | CWEs: {enriched.cwe_ids}")

if __name__ == "__main__":
    run_rq1_eval("data/extract_meta")
