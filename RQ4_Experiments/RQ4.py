#!/usr/bin/env python3
"""
POLAR RQ4: Mitigation Recommendation Efficacy Evaluation
Evaluates mitigation retrieval and prioritization capabilities
"""

import json
import numpy as np
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
from collections import defaultdict
from sklearn.metrics import ndcg_score
from scipy.stats import kendalltau
import requests
from datetime import datetime

@dataclass
class ThreatInstance:
    """Represents a threat instance with severity and exploitation scores"""
    threat_id: str
    cve_id: Optional[str]
    vendor: str
    product: str
    versions: List[str]
    static_severity: float  # CVSS-based severity score (sk)
    exploitation_prob: float  # 30-day exploitation probability (pk)
    exposure_factor: float  # αexp ∈ {1.5, 1.0, 0.5}
    asset_criticality: float  # βcrit ∈ {2.0, 1.5, 1.0, 0.5}

@dataclass
class MitigationAction:
    """Represents a mitigation action"""
    action_id: str
    action_type: str  # "patch", "workaround", "detection", "isolation"
    description: str
    target_threat: str
    implementation_complexity: str  # "simple", "moderate", "complex"
    business_impact: str  # "low", "medium", "high"
    effectiveness: float  # 0.0 to 1.0
    source: str  # "vendor", "cisa_kev", "nvd", "attack"
    url: Optional[str]
    prerequisites: List[str]

@dataclass
class MitigationRecommendation:
    """Complete mitigation recommendation with prioritization"""
    threat_instance: ThreatInstance
    actions: List[MitigationAction]
    risk_score: float
    priority_rank: int
    justification: str
    dependencies: List[str]

class MitigationRecommendationEvaluator:
    """Evaluates mitigation recommendation efficacy for RQ4"""
    
    def __init__(self, llm_client, knowledge_sources: Dict[str, str]):
        self.llm_client = llm_client
        self.knowledge_sources = knowledge_sources
        
    def retrieve_mitigations(self, threat_instance: ThreatInstance) -> List[MitigationAction]:
        """
        Retrieve mitigation actions for a given threat instance
        
        Args:
            threat_instance: The threat to find mitigations for
            
        Returns:
            List of available mitigation actions
        """
        
        prompt = f"""
        System role: You are a remediation researcher. Retrieve patches, workarounds, detections, and 
        monitoring guidance from authoritative sources for the given threat.

        Threat Instance:
        - CVE ID: {threat_instance.cve_id}
        - Vendor: {threat_instance.vendor}
        - Product: {threat_instance.product}
        - Versions: {threat_instance.versions}
        - Static Severity: {threat_instance.static_severity}
        - Exploitation Probability: {threat_instance.exploitation_prob}

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
        
        Include all available mitigation types with realistic complexity and impact assessments.
        """
        
        try:
            response = self.llm_client.generate(prompt, temperature=0.1)
            actions_data = json.loads(self._extract_json_from_response(response))
            
            if isinstance(actions_data, dict):
                actions_data = [actions_data]
                
            actions = []
            for data in actions_data:
                action = MitigationAction(
                    action_id=data.get('action_id', ''),
                    action_type=data.get('action_type', 'patch'),
                    description=data.get('description', ''),
                    target_threat=threat_instance.threat_id,
                    implementation_complexity=data.get('implementation_complexity', 'moderate'),
                    business_impact=data.get('business_impact', 'medium'),
                    effectiveness=float(data.get('effectiveness', 0.5)),
                    source=data.get('source', 'unknown'),
                    url=data.get('url'),
                    prerequisites=data.get('prerequisites', [])
                )
                actions.append(action)
                
            return actions
            
        except Exception as e:
            print(f"Error retrieving mitigations: {e}")
            return []
    
    def prioritize_threats(self, threat_instances: List[ThreatInstance], 
                          mitigation_actions: Dict[str, List[MitigationAction]]) -> List[MitigationRecommendation]:
        """
        Prioritize threats and generate ordered mitigation recommendations
        
        Args:
            threat_instances: List of threats to prioritize
            mitigation_actions: Dictionary mapping threat_id to available actions
            
        Returns:
            Ordered list of mitigation recommendations
        """
        
        recommendations = []
        
        for threat in threat_instances:
            # Calculate risk score: Risk = static_severity * exploitation_prob * exposure * criticality
            risk_score = (threat.static_severity * threat.exploitation_prob * 
                         threat.exposure_factor * threat.asset_criticality)
            
            actions = mitigation_actions.get(threat.threat_id, [])
            
            # Generate justification using LLM
            justification = self._generate_prioritization_justification(threat, actions, risk_score)
            
            recommendation = MitigationRecommendation(
                threat_instance=threat,
                actions=actions,
                risk_score=risk_score,
                priority_rank=0,  # Will be set after sorting
                justification=justification,
                dependencies=self._extract_dependencies(actions)
            )
            recommendations.append(recommendation)
        
        # Sort by risk score and apply tie-breakers
        recommendations = self._apply_prioritization_logic(recommendations)
        
        # Assign final priority ranks
        for idx, rec in enumerate(recommendations):
            rec.priority_rank = idx + 1
            
        return recommendations
    
    def evaluate_ranking_correctness(self, predicted_rankings: List[MitigationRecommendation],
                                   ground_truth_rankings: List[Dict]) -> Dict[str, float]:
        """
        Evaluate the correctness of threat prioritization rankings
        
        Args:
            predicted_rankings: POLAR's prioritized recommendations
            ground_truth_rankings: Expert-annotated ground truth rankings
            
        Returns:
            Dictionary with NDCG@5, NDCG@10, and Kendall's τ scores
        """
        
        # Extract risk scores and convert to rankings
        predicted_scores = [rec.risk_score for rec in predicted_rankings]
        predicted_ids = [rec.threat_instance.threat_id for rec in predicted_rankings]
        
        # Map ground truth to same order
        gt_scores = []
        gt_dict = {item['threat_id']: item['priority_score'] for item in ground_truth_rankings}
        
        for threat_id in predicted_ids:
            gt_scores.append(gt_dict.get(threat_id, 0.0))
        
        # Calculate NDCG scores
        try:
            ndcg_5 = ndcg_score([gt_scores], [predicted_scores], k=5)
            ndcg_10 = ndcg_score([gt_scores], [predicted_scores], k=10)
        except Exception as e:
            print(f"NDCG calculation error: {e}")
            ndcg_5 = ndcg_10 = 0.0
        
        # Calculate Kendall's τ for global consistency  
        try:
            kendall_tau, _ = kendalltau(predicted_scores, gt_scores)
            if np.isnan(kendall_tau):
                kendall_tau = 0.0
        except Exception as e:
            print(f"Kendall's τ calculation error: {e}")
            kendall_tau = 0.0
        
        return {
            'ndcg_5': ndcg_5,
            'ndcg_10': ndcg_10,
            'kendall_tau': kendall_tau
        }
    
    def evaluate_mitigation_retrieval(self, test_cases: List[Dict]) -> Dict[str, float]:
        """
        Evaluate mitigation retrieval recall across four categories
        
        Args:
            test_cases: List of test cases with threat instances and expected mitigations
            
        Returns:
            Dictionary with recall scores for each mitigation category
        """
        
        categories = ['cve_to_patch', 'attack_mapping', 'remediation_note', 'vendor_advisory']
        results = {cat: {'retrieved': [], 'expected': []} for cat in categories}
        
        for case in test_cases:
            threat_instance = case['threat_instance']
            expected_mitigations = case['expected_mitigations']
            
            # Retrieve mitigations using POLAR
            retrieved_actions = self.retrieve_mitigations(threat_instance)
            
            # Categorize retrieved and expected mitigations
            retrieved_by_category = self._categorize_mitigations(retrieved_actions)
            expected_by_category = self._categorize_mitigations(expected_mitigations)
            
            # Store for recall calculation
            for category in categories:
                results[category]['retrieved'].append(retrieved_by_category.get(category, []))
                results[category]['expected'].append(expected_by_category.get(category, []))
        
        # Calculate recall for each category
        recall_scores = {}
        for category in categories:
            recall_scores[category] = self._calculate_recall(
                results[category]['retrieved'], 
                results[category]['expected']
            )
        
        return recall_scores
    
    def run_full_evaluation(self, test_dataset: Dict) -> Dict[str, float]:
        """
        Run complete RQ4 evaluation covering ranking correctness and retrieval recall
        
        Args:
            test_dataset: Dictionary with 'ranking_cases' and 'retrieval_cases'
            
        Returns:
            Complete evaluation results matching Table 3 format
        """
        
        print("Evaluating Mitigation Recommendation Efficacy...")
        
        # Evaluate ranking correctness
        ranking_results = []
        for case in test_dataset['ranking_cases']:
            threats = case['threat_instances']
            ground_truth = case['ground_truth_ranking']
            
            # Retrieve mitigations for all threats
            mitigation_actions = {}
            for threat in threats:
                mitigation_actions[threat.threat_id] = self.retrieve_mitigations(threat)
            
            # Generate prioritized recommendations
            recommendations = self.prioritize_threats(threats, mitigation_actions)
            
            # Evaluate against ground truth
            ranking_metrics = self.evaluate_ranking_correctness(recommendations, ground_truth)
            ranking_results.append(ranking_metrics)
        
        # Average ranking metrics across test cases
        avg_ranking = {}
        if ranking_results:
            for metric in ['ndcg_5', 'ndcg_10', 'kendall_tau']:
                avg_ranking[metric] = np.mean([r[metric] for r in ranking_results])
        
        # Evaluate retrieval recall
        retrieval_metrics = self.evaluate_mitigation_retrieval(test_dataset['retrieval_cases'])
        
        # Combine results in paper format
        results = {
            'ranking_correctness': {
                'ndcg_5': avg_ranking.get('ndcg_5', 0.0),
                'kendall_tau': avg_ranking.get('kendall_tau', 0.0)
            },
            'mitigation_retrieval_recall': {
                'cve_to_patch': retrieval_metrics.get('cve_to_patch', 0.0),
                'attack_mapping': retrieval_metrics.get('attack_mapping', 0.0),
                'remediation_note': retrieval_metrics.get('remediation_note', 0.0),
                'vendor_advisory': retrieval_metrics.get('vendor_advisory', 0.0)
            }
        }
        
        return results
    
    def _generate_prioritization_justification(self, threat: ThreatInstance, 
                                             actions: List[MitigationAction], 
                                             risk_score: float) -> str:
        """Generate natural language justification for prioritization decision"""
        
        prompt = f"""
        Provide a concise justification for prioritizing this threat based on its risk characteristics:
        
        Threat: {threat.vendor} {threat.product} (CVE: {threat.cve_id})
        Static Severity: {threat.static_severity:.2f}
        Exploitation Probability: {threat.exploitation_prob:.2f}
        Risk Score: {risk_score:.2f}
        Available Actions: {len(actions)} mitigations found
        
        Explain in 1-2 sentences why this threat should be prioritized at this level.
        Focus on the most significant risk factors.
        """
        
        try:
            response = self.llm_client.generate(prompt, temperature=0.1)
            return response.strip()
        except Exception as e:
            return f"Risk score {risk_score:.2f} based on severity and exploitation probability."
    
    def _extract_dependencies(self, actions: List[MitigationAction]) -> List[str]:
        """Extract dependencies from mitigation actions"""
        dependencies = []
        for action in actions:
            if action.prerequisites:
                dependencies.extend(action.prerequisites)
        return list(set(dependencies))
    
    def _apply_prioritization_logic(self, recommendations: List[MitigationRecommendation]) -> List[MitigationRecommendation]:
        """
        Apply prioritization logic with tie-breakers as described in the paper
        Primary: Risk score
        Tie-breakers: (1) patch availability, (2) implementation complexity, 
                      (3) exploitation velocity, (4) business disruption
        """
        
        def prioritization_key(rec: MitigationRecommendation):
            # Primary key: Risk score (higher = higher priority)
            primary = -rec.risk_score
            
            # Tie-breaker 1: Patch availability (patch > workaround > none)
            patch_priority = 0
            for action in rec.actions:
                if action.action_type == "patch":
                    patch_priority = 3
                    break
                elif action.action_type == "workaround":
                    patch_priority = max(patch_priority, 2)
                elif action.action_type in ["detection", "isolation"]:
                    patch_priority = max(patch_priority, 1)
            
            # Tie-breaker 2: Implementation complexity (simple > moderate > complex)
            complexity_priority = 0
            for action in rec.actions:
                if action.implementation_complexity == "simple":
                    complexity_priority = 3
                    break
                elif action.implementation_complexity == "moderate":
                    complexity_priority = max(complexity_priority, 2)
                else:  # complex
                    complexity_priority = max(complexity_priority, 1)
            
            # Tie-breaker 3: Exploitation velocity (higher probability = faster)
            exploitation_velocity = -rec.threat_instance.exploitation_prob
            
            # Tie-breaker 4: Business disruption (lower impact = higher priority)
            business_disruption = 0
            for action in rec.actions:
                if action.business_impact == "low":
                    business_disruption = 3
                    break
                elif action.business_impact == "medium":
                    business_disruption = max(business_disruption, 2)
                else:  # high
                    business_disruption = max(business_disruption, 1)
            
            return (primary, -patch_priority, -complexity_priority, exploitation_velocity, -business_disruption)
        
        return sorted(recommendations, key=prioritization_key)
    
    def _categorize_mitigations(self, mitigations: Union[List[MitigationAction], List[Dict]]) -> Dict[str, List[str]]:
        """Categorize mitigations into the four evaluation categories"""
        
        categories = {
            'cve_to_patch': [],
            'attack_mapping': [],
            'remediation_note': [],
            'vendor_advisory': []
        }
        
        for mitigation in mitigations:
            if isinstance(mitigation, MitigationAction):
                action_type = mitigation.action_type
                source = mitigation.source
                action_id = mitigation.action_id
            else:  # Dictionary format
                action_type = mitigation.get('action_type', '')
                source = mitigation.get('source', '')
                action_id = mitigation.get('action_id', '')
            
            # Categorize based on action type and source
            if action_type == "patch" and source in ["vendor", "nvd"]:
                categories['cve_to_patch'].append(action_id)
            elif source == "attack" or "T1" in str(mitigation):
                categories['attack_mapping'].append(action_id)
            elif source == "cisa_kev" or "remediation" in action_type:
                categories['remediation_note'].append(action_id)
            elif source == "vendor":
                categories['vendor_advisory'].append(action_id)
        
        return categories
    
    def _calculate_recall(self, retrieved_lists: List[List[str]], expected_lists: List[List[str]]) -> float:
        """Calculate recall for a category across all test cases"""
        
        if not retrieved_lists or not expected_lists:
            return 0.0
        
        recall_scores = []
        for retrieved, expected in zip(retrieved_lists, expected_lists):
            if not expected:  # No expected mitigations
                recall_scores.append(1.0 if not retrieved else 0.0)
            else:
                retrieved_set = set(retrieved)
                expected_set = set(expected)
                intersection = len(retrieved_set & expected_set)
                recall = intersection / len(expected_set)
                recall_scores.append(recall)
        
        return np.mean(recall_scores)
    
    def _extract_json_from_response(self, response: str) -> str:
        """Extract JSON content from LLM response"""
        import re
        json_pattern = r'[\[\{].*[\]\}]'
        matches = re.findall(json_pattern, response, re.DOTALL)
        if matches:
            return matches[0]
        return response.strip()


# Example usage and testing
if __name__ == "__main__":
    # Mock LLM client for testing
    class MockLLMClient:
        def generate(self, prompt: str, temperature: float = 0.0) -> str:
            if "retrieve patches" in prompt.lower():
                return '''[
                    {
                        "action_id": "patch_cve_2021_34527",
                        "action_type": "patch",
                        "description": "Install KB5004945 security update",
                        "implementation_complexity": "simple",
                        "business_impact": "low",
                        "effectiveness": 0.95,
                        "source": "vendor",
                        "url": "https://support.microsoft.com/kb/5004945",
                        "prerequisites": ["system_restart"]
                    },
                    {
                        "action_id": "workaround_disable_spooler",
                        "action_type": "workaround", 
                        "description": "Disable Print Spooler service",
                        "implementation_complexity": "moderate",
                        "business_impact": "high",
                        "effectiveness": 0.85,
                        "source": "cisa_kev",
                        "url": "https://cisa.gov/kev",
                        "prerequisites": ["admin_access"]
                    }
                ]'''
            else:
                return "High severity vulnerability with active exploitation requires immediate patching."
    
    # Initialize evaluator
    knowledge_sources = {
        "nvd": "https://nvd.nist.gov/",
        "cisa_kev": "https://cisa.gov/known-exploited-vulnerabilities-catalog",
        "attack": "https://attack.mitre.org/",
        "vendor_advisories": "https://msrc.microsoft.com/"
    }
    
    evaluator = MitigationRecommendationEvaluator(MockLLMClient(), knowledge_sources)
    
    # Example test dataset
    test_threat = ThreatInstance(
        threat_id="msft_print_spooler_2021",
        cve_id="CVE-2021-34527",
        vendor="Microsoft",
        product="Windows Print Spooler",
        versions=["Windows 10", "Windows 11"],
        static_severity=8.8,  # CVSS score
        exploitation_prob=0.85,  # High probability
        exposure_factor=1.5,  # High exposure
        asset_criticality=2.0  # Critical asset
    )
    
    test_dataset = {
        'ranking_cases': [
            {
                'threat_instances': [test_threat],
                'ground_truth_ranking': [
                    {'threat_id': 'msft_print_spooler_2021', 'priority_score': 10.0}
                ]
            }
        ],
        'retrieval_cases': [
            {
                'threat_instance': test_threat,
                'expected_mitigations': [
                    {
                        'action_id': 'patch_cve_2021_34527',
                        'action_type': 'patch',
                        'source': 'vendor'
                    },
                    {
                        'action_id': 'attack_t1210_mitigation',
                        'action_type': 'detection',
                        'source': 'attack'
                    }
                ]
            }
        ]
    }
    
    # Run evaluation
    results = evaluator.run_full_evaluation(test_dataset)
    print("RQ4 Evaluation Results:")
    print(json.dumps(results, indent=2))