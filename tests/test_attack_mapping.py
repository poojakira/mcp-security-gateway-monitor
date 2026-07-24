import pytest
from attack_core import ATTACKIndex, ATTACKLoader
from attack_mapping.enricher import ATTACKEnricher


@pytest.fixture
def enricher():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    return ATTACKEnricher(index)


class TestMCPGatewayEnricher:
    def test_prompt_injection(self, enricher):
        mappings = enricher.enrich("prompt_injection_detected", {"confidence": 0.9})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1059" in technique_ids
        assert "T1190" in technique_ids
        assert "T1566" in technique_ids

    def test_tool_call_exfil(self, enricher):
        mappings = enricher.enrich("tool_call_exfil_attempt", {"confidence": 0.85})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1041" in technique_ids
        assert "T1048.003" in technique_ids

    def test_auth_bypass(self, enricher):
        mappings = enricher.enrich("mcp_auth_bypass", {"confidence": 0.95})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1550" in technique_ids
        assert "T1078.004" in technique_ids
