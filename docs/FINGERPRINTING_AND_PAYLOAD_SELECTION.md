# Fingerprinting and Intelligent Payload Selection

## Overview

CyberShellV2 now includes advanced fingerprinting and intelligent payload selection capabilities that dramatically improve exploitation success rates by tailoring attacks to specific target technologies and versions.

## Key Features

### 🔍 Target Fingerprinting
- **Passive Fingerprinting**: Identifies technologies from headers, cookies, and HTML content
- **Active Fingerprinting**: Probes common endpoints for additional information
- **SSL/TLS Analysis**: Extracts certificate information to identify CDN/cloud providers
- **Technology Detection**: Identifies servers, frameworks, CMS, databases, and libraries
- **Version Detection**: Extracts specific version numbers when available
- **WAF Detection**: Identifies Web Application Firewalls (CloudFlare, AWS WAF, etc.)

### 🎯 Intelligent Payload Selection
- **Version-Specific Payloads**: Selects payloads matching target product/version
- **Confidence Scoring**: Ranks payloads based on multiple factors
- **Adaptive Selection**: Learns from failures and suggests alternatives
- **Context Awareness**: Considers injection context (parameter, header, body, etc.)
- **Historical Learning**: Tracks success rates and improves over time

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Fingerprinter  │────▶│  PayloadManager  │────▶│  Exploitation   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        │                        │                         │
        ▼                        ▼                         ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│TargetFingerprint│     │  VulnerabilityKB │     │  Agent/Plugin   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Implementation Details

### Modified Files

1. **cybershell/vulnerability_kb.py**
   - Added `product` and `version_spec` fields to `VulnPayload`
   - Added `matches_version()` method for version checking
   - Added `get_payloads_by_product()` method
   - Updated JSON/YAML loading to support new fields

2. **cybershell/orchestrator.py**
   - Added `fingerprint_target()` method
   - Integrated fingerprinting before exploitation
   - Passes target_info to AI orchestrator and autonomous engine
   - Caches fingerprints for performance

3. **cybershell/agent.py**
   - Updated `_phase_exploitation()` to use PayloadManager
   - Sub-agents now accept `exploit_payloads` parameter
   - Tracks successful payloads for learning

4. **cybershell/advanced_ai_orchestrator.py**
   - Uses fingerprint data in prompt generation
   - Suggests version-specific payloads to AI models
   - Includes KB alternatives in adaptive payload generation

### New Files

1. **cybershell/fingerprinter.py**
   - Core fingerprinting engine
   - `TargetFingerprint` dataclass
   - Signature database for technology detection
   - SSL/TLS certificate analysis

2. **cybershell/payload_manager.py**
   - Intelligent payload selection and ranking
   - `PayloadScore` calculation system
   - Adaptive payload selection after failures
   - Historical success tracking

## Usage Examples

### Basic Fingerprinting

```python
from cybershell.fingerprinter import Fingerprinter

# Initialize fingerprinter
fp = Fingerprinter({'aggressive': False})

# Fingerprint target
fingerprint = fp.fingerprint("https://example.com")

print(f"Product: {fingerprint.product}")
print(f"Version: {fingerprint.version}")
print(f"Technologies: {fingerprint.technologies}")
```

### Payload Selection

```python
from cybershell.payload_manager import SmartPayloadSelector

# Initialize selector
selector = SmartPayloadSelector()

# Select payloads based on fingerprint
payloads = selector.select_for_target(
    target="https://example.com",
    vulnerability="XSS",
    context={'endpoint_type': 'web'}
)

for p in payloads[:3]:
    print(f"{p['name']}: {p['score']:.3f}")
```

### Full Integration

```python
from cybershell import CyberShell

# Initialize with fingerprinting enabled
config = {
    'fingerprinting': {'enable': True},
    'payload_selection': {'enabled': True}
}

cs = CyberShell(config=config)

# Run exploitation (fingerprinting happens automatically)
result = await cs.run_exploitation("https://example.com")
```

## Configuration

### config.yaml

```yaml
fingerprinting:
  enable: true
  aggressive: false
  use_external_tools: false
  cache_ttl: 300

payload_selection:
  enabled: true
  prefer_version_specific: true
  weights:
    version_weight: 0.35
    pattern_weight: 0.25
    confidence_weight: 0.20
```

## Custom Payloads

Add product/version-specific payloads in `knowledge_base/custom_payloads/`:

```json
{
  "payloads": [
    {
      "category": "XSS",
      "name": "WordPress Comment XSS",
      "payload": "<script>alert(1)</script>",
      "product": "wordpress",
      "version_spec": "<5.4.2",
      "confidence_score": 0.85
    }
  ]
}
```

## Scoring Algorithm

Payloads are scored based on:

1. **Version Match (35%)**: Product and version compatibility
2. **Pattern Match (25%)**: Detection pattern relevance
3. **Base Confidence (20%)**: Knowledge base confidence
4. **Tag Match (10%)**: Tag relevance to target
5. **Context Match (5%)**: Injection context appropriateness
6. **Historical Success (5%)**: Past performance

## Benefits

- **Higher Success Rate**: Version-specific payloads have higher success probability
- **Fewer False Positives**: Targeted payloads reduce noise
- **Faster Exploitation**: Skip ineffective payloads
- **WAF Evasion**: Adapt payloads based on detected WAF
- **Continuous Learning**: System improves over time

## Safety Considerations

- Fingerprinting respects scope configuration
- No aggressive scanning without explicit permission
- Rate limiting applied to fingerprinting requests
- Private IP ranges excluded by default
- Cache used to minimize requests

## Future Enhancements

- [ ] Integration with external tools (WhatWeb, Wappalyzer)
- [ ] Machine learning for payload generation
- [ ] Automated payload mutation based on WAF
- [ ] Cross-reference with CVE database
- [ ] Browser fingerprinting for client-side attacks

## Troubleshooting

### Fingerprinting Not Working
- Check network connectivity
- Verify target is in scope
- Increase timeout in config
- Check for WAF blocking requests

### Payloads Not Version-Specific
- Ensure fingerprinting is enabled
- Check if product/version detected
- Verify custom payloads have version_spec
- Review scoring weights in config

### Performance Issues
- Enable fingerprint caching
- Reduce aggressive scanning
- Limit parallel exploits
- Use payload selection caching

## Contributing

To add new signatures or payloads:

1. Add signatures to `fingerprinter.py`
2. Add payloads to `vulnerability_kb.py` or custom JSON
3. Test with example scripts
4. Submit PR with test results

## License

MIT - For authorized security testing only
