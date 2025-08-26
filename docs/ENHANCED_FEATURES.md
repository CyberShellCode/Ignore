ENHANCED_FEATURES_DOCUMENTATION = """
# CyberShellV2 Enhanced Features Documentation

## Overview

CyberShellV2 includes several major enhancements over the base framework:

1. **Context-Aware Payload Adaptation**
2. **External Tools Integration (Nmap & SQLMap)**
3. **Advanced IDOR/BOLA Hunting**
4. **Enhanced Plugin System**
5. **Comprehensive CLI Interface**

## Context-Aware Payload Adaptation

### Overview
The enhanced payload manager automatically adapts generic payloads from the knowledge base to match specific target contexts, dramatically improving success rates.

### Key Features
- **Database-specific adaptation**: Converts MySQL payloads to PostgreSQL, MSSQL, etc.
- **Quote context detection**: Automatically handles single/double quote contexts
- **WAF evasion**: Applies evasion techniques based on detected WAF
- **Callback integration**: Replaces placeholders with actual OAST/collaborator URLs
- **Success tracking**: Learns from successful/failed attempts

### Usage Examples

```python
from cybershell.enhanced_payload_manager import PayloadContext, EnhancedPayloadManager

# Create context for payload adaptation
context = PayloadContext(
    target_url="http://target.com/api/users",
    parameter_name="id",
    injection_context="parameter",
    database_type="postgresql",
    collaborator_url="https://abc123.oast.site"
)

# Get adapted payloads
adapted_payloads = payload_manager.get_adapted_payloads(
    VulnCategory.SQLI,
    fingerprint,
    context,
    top_n=5
)

for payload, confidence in adapted_payloads:
    print(f"Payload: {payload}")
    print(f"Confidence: {confidence}")
```

### CLI Usage

```bash
# Use enhanced payloads in CTF mode
python -m cybershell ctf http://target.com --adapt-payloads --collaborator-url https://abc123.oast.site

# Use in bug bounty hunting
python -m cybershell hunt https://target.com --adapt-payloads --collaborator-url https://abc123.oast.site
```

## External Tools Integration

### Overview
Seamless integration with industry-standard tools (Nmap and SQLMap) with proper rate limiting for bug bounty programs.

### Features
- **Rate-limited execution**: Respects target resources and program guidelines
- **Fingerprint enhancement**: Results improve CyberShell's fingerprinting
- **Automated tool selection**: Chooses appropriate scan types based on context
- **Unified reporting**: Combines tool results with CyberShell findings

### Usage Examples

```python
from cybershell.external_tools import ToolOrchestrator

# Run comprehensive scan with both tools
orchestrator = ToolOrchestrator(config)
results = await orchestrator.comprehensive_scan("target.com")

# Run individual tools
nmap_result = await orchestrator.nmap.scan_target("target.com", "service_detection")
sqlmap_result = await orchestrator.sqlmap.test_sql_injection("http://target.com?id=1")
```

### CLI Usage

```bash
# Run external tools only
python -m cybershell tools https://target.com --nmap --sqlmap

# Integrate with CyberShell scanning
python -m cybershell hunt https://target.com --use-external-tools

# Comprehensive scan with all features
python -m cybershell comprehensive https://target.com --external-tools --adapt-payloads
```

## Advanced IDOR/BOLA Hunting

### Overview
Comprehensive IDOR hunting system with authentication, endpoint discovery, and JWT analysis.

### Key Features
- **Smart credential management**: Attempts default/weak credentials based on fingerprinting
- **Lockout prevention**: Tracks failed attempts and implements backoff
- **Endpoint discovery**: Crawls, analyzes JavaScript, discovers GraphQL
- **JWT analysis**: Decodes and analyzes JWT tokens for security issues
- **Systematic IDOR testing**: Tests object ID manipulation across all endpoints

### Methodology

1. **Authentication Phase**:
   - Attempt provided credentials
   - Fall back to fingerprint-based defaults
   - Implement lockout-aware pacing

2. **Discovery Phase**:
   - Authenticated crawling
   - JavaScript analysis for API endpoints
   - GraphQL introspection
   - Common API pattern testing

3. **Testing Phase**:
   - Generate test object IDs
   - Systematic IDOR testing
   - JWT claims vs parameter analysis
   - Evidence collection and validation

### Usage Examples

```python
from cybershell.advanced_idor_hunter import IDORHunter, Credential

# Hunt with manual credentials
hunter = IDORHunter()
credentials = [Credential("admin", "password123")]

results = await hunter.hunt_idor(
    "http://target.com",
    provided_credentials=credentials
)

# Automatic hunting with defaults
results = await hunter.hunt_idor(
    "http://target.com",
    fingerprint=target_fingerprint
)
```

### CLI Usage

```bash
# IDOR hunting with credentials
python -m cybershell idor https://target.com --username admin --password admin123

# Use credentials file
python -m cybershell idor https://target.com --credentials-file creds.txt

# Advanced options
python -m cybershell idor https://target.com --jwt-analysis --graphql-introspection --max-object-ids 20
```

## Enhanced Plugin System

### Overview
Plugins now leverage enhanced payload management and external tool integration for improved effectiveness.

### Key Improvements
- **Context-aware payload selection**: Plugins use enhanced payload manager
- **Fingerprint integration**: Payloads adapted based on target fingerprint
- **Success tracking**: Plugins learn from previous attempts
- **External tool cooperation**: Plugins can leverage tool results

### Creating Enhanced Plugins

```python
from cybershell.plugins import PluginBase, PluginResult
from cybershell.enhanced_payload_manager import PayloadContext

class MyEnhancedPlugin(PluginBase):
    name = "MyEnhancedPlugin"
    
    async def run(self, **kwargs) -> PluginResult:
        target = kwargs.get("target")
        enhanced_payload_manager = kwargs.get("enhanced_payload_manager")
        fingerprint = kwargs.get("fingerprint")
        
        # Create context
        context = PayloadContext(
            target_url=target,
            parameter_name=kwargs.get("parameter", "id"),
            collaborator_url=kwargs.get("collaborator_url")
        )
        
        # Get adapted payloads
        if enhanced_payload_manager:
            adapted_payloads = enhanced_payload_manager.get_adapted_payloads(
                VulnCategory.SQLI,
                fingerprint,
                context,
                top_n=5
            )
            
            # Test each payload
            for payload_text, confidence in adapted_payloads:
                result = await self.test_payload(target, payload_text)
                if result['vulnerable']:
                    enhanced_payload_manager.update_payload_success(
                        payload_text, target, True
                    )
                    return PluginResult(self.name, True, result)
        
        return PluginResult(self.name, False, {"reason": "no_vulnerability"})
```

## CLI Interface

### Overview
Comprehensive command-line interface supporting all enhanced features.

### Available Modes

1. **CTF Mode**: `python -m cybershell ctf <target>`
2. **Hunt Mode**: `python -m cybershell hunt <target>`
3. **IDOR Mode**: `python -m cybershell idor <target>`
4. **Tools Mode**: `python -m cybershell tools <target>`
5. **Comprehensive Mode**: `python -m cybershell comprehensive <target>`
6. **Exploit Mode**: `python -m cybershell exploit <target>`

### Global Options

- `--config`: Configuration file path
- `--output`: Output file path
- `--format`: Output format (json, markdown, html)
- `--verbose`: Verbose output
- `--debug`: Debug output
- `--safe-mode`: Enable safe mode
- `--rate-limit`: Requests per second limit
- `--collaborator-url`: OAST collaborator URL

### Examples

```bash
# Basic CTF with enhanced features
python -m cybershell ctf http://ctf.local --adapt-payloads --collaborator-url https://abc123.oast.site

# Bug bounty hunting with all features
python -m cybershell hunt https://target.com \\
  --scope "*.target.com" \\
  --use-external-tools \\
  --adapt-payloads \\
  --chain-exploits

# IDOR hunting with authentication
python -m cybershell idor https://app.target.com \\
  --username admin \\
  --password admin123 \\
  --jwt-analysis \\
  --graphql-introspection

# Comprehensive scan with all features
python -m cybershell comprehensive https://target.com \\
  --fingerprint \\
  --external-tools \\
  --idor-hunting \\
  --adapt-payloads \\
  --credentials admin:admin123 \\
  --report-format html
```

## Configuration

### Enhanced Configuration Options

```yaml
# Enhanced payload configuration
payload_enhancement:
  enabled: true
  context_adaptation:
    database_specific: true
    waf_evasion: true
    encoding_chains: true
  success_tracking:
    enabled: true
    history_file: "./payload_history.json"

# External tools configuration
external_tools:
  enabled: true
  nmap_path: "nmap"
  sqlmap_path: "sqlmap"
  tool_rate_limiting:
    requests_per_second: 2
    burst_size: 5

# IDOR hunting configuration
idor_hunting:
  enabled: true
  authentication:
    attempt_default_credentials: true
    max_credential_attempts: 5
    lockout_detection: true
  testing:
    max_object_id_tests: 10
    response_similarity_threshold: 0.8
```

## Performance and Safety

### Rate Limiting
All enhanced features respect rate limiting to avoid overwhelming targets:

- **External tools**: 1-2 requests per second maximum
- **IDOR hunting**: Conservative pacing with lockout detection
- **Payload testing**: Configurable rate limits with burst allowance

### Error Handling
Comprehensive error handling with graceful degradation:

- **Tool failures**: Fall back to CyberShell-only scanning
- **Authentication failures**: Lockout detection and backoff
- **Payload adaptation errors**: Fall back to original payloads

### Memory Management
Efficient memory usage even during large scans:

- **Streaming results**: Process results as they come
- **Limited caching**: Reasonable cache sizes with TTL
- **Cleanup**: Automatic cleanup of temporary files

## Best Practices

1. **Always set collaborator URL** for accurate callback testing
2. **Use appropriate rate limits** for bug bounty programs (2-5 RPS)
3. **Enable payload adaptation** for better success rates
4. **Combine fingerprinting with external tools** for comprehensive coverage
5. **Use safe mode** when testing production systems
6. **Provide credentials** for authenticated testing when authorized

## Troubleshooting

### Common Issues

1. **Tool not found errors**: Install Nmap/SQLMap or update paths in config
2. **Rate limit exceeded**: Reduce rate limit settings
3. **Authentication failures**: Check credentials and lockout status
4. **Payload adaptation failures**: Verify fingerprint quality

### Debug Mode

```bash
python -m cybershell --debug comprehensive https://target.com
```

This provides detailed logging for troubleshooting issues.
"""

# =============================================================================
# Save Enhanced Features Documentation
# =============================================================================

def save_documentation():
    """Save enhanced features documentation"""
    docs_dir = Path("docs")
    docs_dir.mkdir(exist_ok=True)
    
    with open(docs_dir / "ENHANCED_FEATURES.md", "w") as f:
        f.write(ENHANCED_FEATURES_DOCUMENTATION)
    
    print("Documentation saved to docs/ENHANCED_FEATURES.md")

# =============================================================================
# Pytest Configuration
# Save as: pytest.ini
# =============================================================================

PYTEST_CONFIG = """
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --tb=short
    --strict-markers
    --disable-warnings
markers =
    unit: Unit tests
    integration: Integration tests
    performance: Performance tests
    external: Tests requiring external tools
asyncio_mode = auto
"""

# =============================================================================
# Requirements for Testing
# Save as: requirements-test.txt
# =============================================================================

REQUIREMENTS_TEST = """
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
pytest-mock>=3.11.0
pytest-benchmark>=4.0.0
responses>=0.23.0
"""

if __name__ == "__main__":
    save_documentation()
