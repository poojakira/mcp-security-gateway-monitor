from attack_core import ATTACKLoader, ATTACKIndex
from attack_mapping.enricher import ATTACKEnricher
from attack_mapping.reporter import NavigatorLayerReporter

loader = ATTACKLoader()
index = ATTACKIndex(loader)
enricher = ATTACKEnricher(index)
reporter = NavigatorLayerReporter()

all_mappings = []
for ft in ['prompt_injection_detected', 'tool_call_exfil_attempt', 'unauthorized_mcp_tool_invoke', 'mcp_auth_bypass', 'indirect_prompt_injection', 'system_prompt_extraction', 'excessive_tool_invocation', 'mcp_session_hijack', 'rogue_mcp_server', 'context_window_poisoning']:
    mappings = enricher.enrich(ft, {'confidence': 0.8})
    all_mappings.extend(mappings)

layer = reporter.generate('mcp-security-gateway-monitor', all_mappings)
import json
data = json.loads(layer)
print(f'Techniques mapped: {len(data["techniques"])}')
for t in data['techniques']:
    print(f'  {t["techniqueID"]}: score={t["score"]}')