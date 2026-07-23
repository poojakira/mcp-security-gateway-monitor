## MITRE ATT&CK v19 Coverage

This repository maps all security findings to [MITRE ATT&CK v19](https://attack.mitre.org/).

| Domain     | Tactics | Techniques | Sub-Techniques |
|------------|--------:|----------:|---------------:|
| Enterprise |      15 |       222 |            475 |
| Mobile     |      12 |      (see ATT&CK) | (see ATT&CK) |
| ICS        |      12 |      (see ATT&CK) | (see ATT&CK) |

**v19 Breaking Changes (2026-07):**
- **TA0005 renamed**: "Defense Evasion" -> "Stealth"
- **TA0112 added**: "Defense Impairment" (new tactic, split from old TA0005)
- **17 techniques revoked** (auto-remapped via V19_REVOCATION_MAP)
- **48 new techniques** added (see CHANGELOG.md)

### Export ATT&CK Navigator Layer

```bash
python -m attack_mapping.reporter --output navigator_layer.json
```

Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage. Layers generated with Navigator v4.9 format (attack: "19").

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

### MCP Security Gateway Specific Mappings (v19)

| Finding Type | Techniques (v19) |
|--------------|------------------|
| prompt_injection_detected | T1059, T1190, T1566, **T1684** |
| tool_call_exfil_attempt | T1041, T1048.003 |
| unauthorized_mcp_tool_invoke | T1078, T1203 |
| mcp_auth_bypass | T1550, T1078.004 |
| indirect_prompt_injection | T1059, **T1684/002** |
| system_prompt_extraction | T1552, T1083 |
| excessive_tool_invocation | T1499, T1078, **T1687** |
| mcp_session_hijack | T1563, T1550.004 |
| rogue_mcp_server | T1583, T1608 |
| context_window_poisoning | T1565, T1059, **T1683** |

**New v19 additions in bold:**
- **T1684** (Social Engineering) and **T1684/002** (Email Spoofing) for prompt injection and indirect injection
- **T1687** (Exploitation for Defense Impairment) for excessive tool invocation as defense impairment
- **T1683** (Generate Content) for context window poisoning via AI-generated content

### Migration from v18

See [MIGRATION_GUIDE.md](../attack-v19-core/MIGRATION_GUIDE.md) in attack-v19-core for full migration steps.

Key remappings:
- T1562, T1562.001, T1089, T1054 -> T1685 (Disable or Modify Tools)
- T1070.001 -> T1685.005 (Clear Windows Event Logs)
- T1070.002 -> T1685.006 (Clear Linux/Mac Logs)
- T1534 -> T1684.001 (Social Engineering: Impersonation)
- T1566.003 -> T1684.002 (Social Engineering: Email Spoofing)
- T1566.002 -> T1684/002 (Email Spoofing sub-technique)