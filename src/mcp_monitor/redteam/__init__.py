"""Red Team Attack Simulator — real-world attack pattern replay."""
from mcp_monitor.redteam.payloads import ATTACK_CATALOG
from mcp_monitor.redteam.simulator import AttackSimulator

__all__ = ["AttackSimulator", "ATTACK_CATALOG"]
