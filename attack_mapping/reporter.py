import json
from typing import List
from attack_core.models import ATTACKMapping


class NavigatorLayerReporter:
    """Outputs ATT&CK Navigator layer JSON v4.5"""
    def generate(self, repo_name: str, mappings: List[ATTACKMapping]) -> str:
        techniques = []
        seen = set()
        for m in mappings:
            tid = m.subtechnique_id or m.technique_id
            if tid in seen:
                continue
            seen.add(tid)
            techniques.append({
                "techniqueID": tid,
                "score": int(m.confidence * 100),
                "comment": f"{repo_name} detection",
                "enabled": True,
            })
        layer = {
            "name": f"{repo_name} ATT&CK Coverage",
            "versions": {"attack": "19", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "techniques": techniques,
        }
        return json.dumps(layer, indent=2)