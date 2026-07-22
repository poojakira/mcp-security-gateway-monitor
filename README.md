## MITRE ATT&CK v19 Coverage

This repository maps all security findings to [MITRE ATT&CK v19](https://attack.mitre.org/).

| Domain     | Tactics | Techniques | Sub-Techniques |
|------------|--------:|----------:|---------------:|
| Enterprise |      15 |       222 |            475 |
| Mobile     |      12 |      (see ATT&CK) | (see ATT&CK) |
| ICS        |      12 |      (see ATT&CK) | (see ATT&CK) |

### Export ATT&CK Navigator Layer

```bash
python -m attack_mapping.reporter --output navigator_layer.json
```

Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage.

### Finding Schema

Every finding object includes:
```json
{
  "attack_mappings": [
    {
      "tactic_id":         "TA0001",
      "tactic_name":       "Initial Access",
      "technique_id":      "T1059",
      "technique_name":    "Command and Scripting Interpreter",
      "subtechnique_id":   null,
      "subtechnique_name": null,
      "domain":            "enterprise",
      "confidence":        0.85,
      "data_sources":      ["..."],
      "platforms":         ["..."],
      "url":               "https://attack.mitre.org/techniques/T1059/"
    }
  ]
}
```

### MCP Security Gateway Specific Mappings

| Finding Type | Techniques |
|--------------|------------|
| prompt_injection_detected | T1059, T1190, T1566 |
| tool_call_exfil_attempt | T1041, T1048.003 |
| unauthorized_mcp_tool_invoke | T1078, T1203 |
| mcp_auth_bypass | T1550, T1078.004 |
| indirect_prompt_injection | T1059, T1566.002 |
| system_prompt_extraction | T1552, T1083 |
| excessive_tool_invocation | T1499, T1078 |
| mcp_session_hijack | T1563, T1550.004 |
| rogue_mcp_server | T1583, T1608 |
| context_window_poisoning | T1565, T1059 |