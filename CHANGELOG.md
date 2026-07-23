# Changelog - mcp-security-gateway-monitor

## [1.0.0] - 2026-07-22

### Changed - ATT&CK v19 Migration

#### Technique Remappings (Revoked -> New)
| Old ID | New ID | Rule Table Keys Affected |
|--------|--------|-------------------------|
| T1566.002 | T1684/002 | indirect_prompt_injection |

#### New Technique Coverage Added
- **T1684** (Social Engineering): Added to `prompt_injection_detected`
- **T1684/002** (Email Spoofing): Added to `indirect_prompt_injection` (replaces T1566.002)
- **T1687** (Exploitation for Defense Impairment): Added to `excessive_tool_invocation`

#### Rule Table Updates
```python
# BEFORE
"prompt_injection_detected": ["T1059", "T1190", "T1566"],
"indirect_prompt_injection": ["T1059", "T1566.002"],
"excessive_tool_invocation": ["T1499", "T1078"],

# AFTER
"prompt_injection_detected": ["T1059", "T1190", "T1566", "T1684"],
"indirect_prompt_injection": ["T1059", "T1684/002"],
"excessive_tool_invocation": ["T1499", "T1078", "T1687"],
```

### Added
- Detection coverage for AI-specific social engineering (T1684)
- Defense Impairment tactic technique (T1687) for tool abuse scenarios

### Migration
See [attack-v19-core MIGRATION_GUIDE.md](../attack-v19-core/MIGRATION_GUIDE.md) for full migration steps.