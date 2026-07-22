"""
ATT&CK Enricher for mcp-security-gateway-monitor.
Maps MCP gateway findings to MITRE ATT&CK techniques.
"""
from attack_core.index import ATTACKIndex
from attack_core.models import ATTACKMapping
from typing import List, Dict, Any


class ATTACKEnricher:
    def __init__(self, index: ATTACKIndex):
        self.index = index
        self._rule_table = {
            "prompt_injection_detected": ["T1059", "T1190", "T1566"],
            "tool_call_exfil_attempt": ["T1041", "T1048.003"],
            "unauthorized_mcp_tool_invoke": ["T1078", "T1203"],
            "mcp_auth_bypass": ["T1550", "T1078.004"],
            "indirect_prompt_injection": ["T1059", "T1566.002"],
            "system_prompt_extraction": ["T1552", "T1083"],
            "excessive_tool_invocation": ["T1499", "T1078"],
            "mcp_session_hijack": ["T1563", "T1550.004"],
            "rogue_mcp_server": ["T1583", "T1608"],
            "context_window_poisoning": ["T1565", "T1059"],
        }

    def enrich(self, finding_type: str, metadata: Dict[str, Any]) -> List[ATTACKMapping]:
        technique_ids = self._rule_table.get(finding_type, [])
        mappings = []
        for tid in technique_ids:
            tech = self.index.get(tid)
            if tech:
                tactic = self.index._tactics.get(tech.tactic_ids[0] if tech.tactic_ids else "", None)
                mappings.append(ATTACKMapping(
                    tactic_id=tech.tactic_ids[0] if tech.tactic_ids else "unknown",
                    tactic_name=tactic.name if tactic else "unknown",
                    technique_id=tech.attack_id,
                    technique_name=tech.name,
                    subtechnique_id=tech.attack_id if tech.is_subtechnique else None,
                    subtechnique_name=tech.name if tech.is_subtechnique else None,
                    domain=tech.domain,
                    confidence=metadata.get("confidence", 0.5),
                    data_sources=tech.data_sources,
                    platforms=tech.platforms,
                    url=tech.url,
                ))
        return mappings