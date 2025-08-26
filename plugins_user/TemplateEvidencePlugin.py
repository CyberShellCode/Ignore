"""
TemplateEvidencePlugin — a lab-safe, authorized plugin template.

How to use:
- Drop this file under plugins_user/.
- Reference it in plans/LLM steps via: {"plugin": "TemplateEvidencePlugin", ...}
- Return details['evidence_score'] in [0,1] with consistent semantics across your plugins.
- Populate auxiliary fields so different scorers (default/high_confidence/weighted_signal) have material.

NOTE: Keep real-world interactions (network, auth, etc.) only in authorized contexts.
"""

from cybershell.plugins import PluginBase, PluginResult

class TemplateEvidencePlugin(PluginBase):
    name = "TemplateEvidencePlugin"

    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get("target", "")
        if not self.in_scope(target):
            return PluginResult(self.name, False, {"reason": "out_of_scope"})

        # Example: read hints or mode from params (purely local/lab-safe here)
        hint = kwargs.get("hint", "baseline")
        confidence = float(kwargs.get("confidence", 0.35))  # let caller override

        details = {
            "hint_used": hint,
            # Signals the scorers can use (fill these when applicable in your real plugin)
            "reflections": [],        # e.g., echoed tokens in responses
            "error_tokens": [],       # e.g., stack traces, SQL errors
            "length_delta": 0.0,      # change in response length between probes
            "headers": {},            # observed interesting headers
            # Crucially: calibrated numeric confidence (0..1)
            "evidence_score": max(0.0, min(1.0, confidence)),
            "notes": "template evidence; replace with authorized logic"
        }
        return PluginResult(self.name, True, details)
