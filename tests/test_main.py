"""
Unit tests for CyberShell CLI and helper functions touched in the PR diff.

Framework: pytest (capsys, monkeypatch, tmp_path). We stick to pytest idioms and do not add new deps.
Focus: print_banner, setup_llm, run_ctf_mode, run_targeted_ctf_test, extract_ctf_flag,
       save_ctf_report, run_standard_mode, run_autonomous_mode, and main() control flow.
"""

import json
import sys
import importlib
from pathlib import Path
from typing import Any
import pytest

# --- dynamic module resolver -------------------------------------------------

def _resolve_main_module() -> Any:
    """
    Try common module paths. Returns imported module or raises ImportError.
    """
    candidates = [
        "cybershell.__main__",
        "cybershell.main",
        "main",
        "app.main",
        "__main__",  # fallback if tests are executed oddly
    ]
    last_err = None
    for name in candidates:
        try:
            return importlib.import_module(name)
        except ImportError as e:
            last_err = e
    raise ImportError(f"Could not import target module from any of {candidates}: {last_err}")

main_mod = _resolve_main_module()

# --- utilities ---------------------------------------------------------------

class DummyBot:
    """A minimal stub for CyberShell used in targeted tests."""

    def __init__(self) -> None:
        self._executed = []
        self._llm = None
        self._outcomes = {}
        self._hunt_autonomous_result = None
        self._execute_result = None

    def set_llm(self, llm: Any) -> None:
        self._llm = llm

    def hunt_autonomous(self, _target: Any, _config: Any) -> Any:
        return self._hunt_autonomous_result or {
            "findings": [],
            "total_bounty_estimate": 0,
            "metrics": {
                "total_attempts": 0,
                "successful_exploits": 0,
                "success_rate": 0.0,
                "exploit_chains": 0,
            },
            "evidence_summary": {"ema": 0.0, "max": 0.0, "trend": "stable"},
            "report": "",
        }

    def execute(self, _target: Any, _llm_step_budget: Any) -> Any:
        return self._execute_result or {
            "evidence_summary": {"ema": 0.0, "max": 0.0, "trend": "stable"},
            "metrics": {
                "total_attempts": 0,
                "successful_exploits": 0,
                "success_rate": 0.0,
                "exploit_chains": 0,
            },
            "report": "",
        }

    def execute_plugin(self, name: Any, params: Any) -> Any:
        self._executed.append((name, dict(params)))
        outcome = self._outcomes.get(name)
        if outcome is None:
            class R:
                def __init__(self, n: Any) -> None:
                    self.name = n
                    self.success = True
                    self.details = {"evidence_score": 1.0, "note": "ok"}

            return R(name)
        return outcome

def _mk_result(name: Any, *, success: bool = True, details: Any = None) -> Any:
    class R:
        def __init__(self) -> None:
            self.name = name
            self.success = success
            self.details = details if details is not None else {}
    return R()

# --- Tests: print_banner -----------------------------------------------------

def test_print_banner_contains_key_lines(capsys: Any) -> None:
    assert hasattr(main_mod, "print_banner")
    main_mod.print_banner()
    out = capsys.readouterr().out
    # Check for stable strings that should always be present
    assert "Autonomous Bug Bounty & CTF Hunting Framework v2.0" in out
    assert "For Authorized Security Testing Only" in out

# --- Tests: extract_ctf_flag -------------------------------------------------

def test_extract_ctf_flag_detects_common_formats(capsys: Any) -> None:
    result = {
        "data": {
            "messages": [
                "flag{abc123}",
                "Some FLAG{UPPER}",
                "picoCTF{pico_rules}",
                "random md5 like 098f6bcd4621d373cade4e832627b4f6",
            ]
        }
    }
    main_mod.extract_ctf_flag(result)
    out = capsys.readouterr().out
    assert "FLAGS FOUND" in out or "🚩" in out
    assert "flag{abc123}" in out
    assert "FLAG{UPPER}" in out
    assert "picoCTF{pico_rules}" in out
    assert "098f6bcd4621d373cade4e832627b4f6" in out

def test_extract_ctf_flag_base64_only_heuristic(capsys: Any) -> None:
    # No direct flags; only base64 strings that decode to CTF/flag markers
    result = {
        "data": {
            "messages": [
                "Q1RGe2Zvby1iYXJ9",     # CTF{foo-bar}
                "ZmxhZ3t0ZXN0fQ==",     # flag{test}
            ]
        }
    }
    main_mod.extract_ctf_flag(result)
    out = capsys.readouterr().out
    assert "No flags found" in out
    assert "Found potential base64 strings" in out
    assert "-> CTF{foo-bar}" in out or "-> flag{test}" in out

def test_extract_ctf_flag_handles_no_flags_and_prints_tips(capsys: Any) -> None:
    main_mod.extract_ctf_flag({"nothing": "here"})
    out = capsys.readouterr().out
    assert "No flags found" in out
    assert "Tips:" in out

# --- Tests: save_ctf_report --------------------------------------------------

def test_save_ctf_report_writes_json(tmp_path: Any, capsys: Any) -> None:
    data = {"target": "http://ctf.local", "success": True, "results": []}
    outfile = tmp_path / "reports" / "ctf.json"
    main_mod.save_ctf_report(data, str(outfile))
    assert outfile.exists()
    loaded = json.loads(outfile.read_text())
    assert loaded["target"] == "http://ctf.local"
    assert loaded["success"] is True
    out = capsys.readouterr().out
    assert "CTF report saved" in out

# --- Tests: run_targeted_ctf_test -------------------------------------------

def test_run_targeted_ctf_test_executes_plugins_and_collects_results() -> None:
    bot = DummyBot()
    bot._outcomes = {
        "SQLiTestPlugin": _mk_result("SQLiTestPlugin", success=True, details={"evidence_score": 0.9}),
        "SQLiExploitPlugin": _mk_result("SQLiExploitPlugin", success=True, details={"evidence_score": 0.95, "details": "Found flag{win}"}),
    }
    res = main_mod.run_targeted_ctf_test(bot, "http://target", "SQLI")
    assert res["target"] == "http://target"
    assert res["vulnerability_type"] == "SQLI"
    assert res["success"] is True
    executed = dict(bot._executed)
    exploit_params = executed.get("SQLiExploitPlugin")
    assert exploit_params is not None
    assert exploit_params.get("technique") == "union_based"
    assert exploit_params.get("extract_data") is True
    assert exploit_params.get("enumerate_db") is True

def test_run_targeted_ctf_test_param_enrichment_xss() -> None:
    bot = DummyBot()
    bot._outcomes = {
        "XSSTestPlugin": _mk_result("XSSTestPlugin", success=True, details={"evidence_score": 0.7}),
        "XSSExploitPlugin": _mk_result("XSSExploitPlugin", success=True, details={"evidence_score": 0.8}),
    }
    main_mod.run_targeted_ctf_test(bot, "http://t", "XSS")
    params = dict(bot._executed).get("XSSExploitPlugin")
    assert params is not None
    assert params.get("steal_session") is True
    assert params.get("screenshot") is True

def test_run_targeted_ctf_test_param_enrichment_rce() -> None:
    bot = DummyBot()
    bot._outcomes = {
        "RCETestPlugin": _mk_result("RCETestPlugin", success=True, details={"evidence_score": 0.7}),
        "RCEExploitPlugin": _mk_result("RCEExploitPlugin", success=True, details={"evidence_score": 0.9}),
    }
    main_mod.run_targeted_ctf_test(bot, "http://t", "RCE")
    params = dict(bot._executed).get("RCEExploitPlugin")
    assert params is not None
    assert params.get("establish_shell") is True
    assert params.get("system_enumeration") is True

def test_run_targeted_ctf_test_param_enrichment_ssrf() -> None:
    bot = DummyBot()
    bot._outcomes = {
        "SSRFTestPlugin": _mk_result("SSRFTestPlugin", success=True, details={"evidence_score": 0.7}),
        "SSRFExploitPlugin": _mk_result("SSRFExploitPlugin", success=True, details={"evidence_score": 0.85}),
    }
    main_mod.run_targeted_ctf_test(bot, "http://t", "SSRF")
    params = dict(bot._executed).get("SSRFExploitPlugin")
    assert params is not None
    assert params.get("access_metadata") is True
    assert params.get("scan_internal") is True

def test_run_targeted_ctf_test_stops_when_test_plugin_fails() -> None:
    bot = DummyBot()
    bot._outcomes = {
        "XSSTestPlugin": _mk_result("XSSTestPlugin", success=False, details={"reason": "no xss"}),
    }
    res = main_mod.run_targeted_ctf_test(bot, "http://t", "XSS")
    executed_names = [name for (name, _params) in bot._executed]
    assert executed_names == ["XSSTestPlugin"]
    assert res["success"] is False

def test_run_targeted_ctf_test_unknown_type_returns_none(capsys: Any) -> None:
    bot = DummyBot()
    ret = main_mod.run_targeted_ctf_test(bot, "http://t", "NOT_A_TYPE")
    assert ret is None
    out = capsys.readouterr().out
    assert "Unknown vulnerability type" in out

# --- Tests: setup_llm --------------------------------------------------------

class _Args:
    def __init__(self, llm: str = "ollama") -> None:
        self.llm = llm

def test_setup_llm_none_returns_none() -> None:
    args = _Args(llm="none")
    bot = DummyBot()
    assert main_mod.setup_llm(args, bot) is None

def test_setup_llm_ollama_reads_env_and_sets_llm(monkeypatch: Any) -> None:
    class StubOllama:
        def __init__(self, model: str, base_url: str) -> None:
            self.model = model
            self.base_url = base_url

    monkeypatch.setenv("OLLAMA_MODEL", "mistral:7b")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://ollama:11434")
    monkeypatch.setattr(main_mod, "OllamaConnector", StubOllama, raising=False)

    args = _Args(llm="ollama")
    bot = DummyBot()
    llm = main_mod.setup_llm(args, bot)
    assert isinstance(llm, StubOllama)
    assert bot._llm is llm
    assert llm.model == "mistral:7b"
    assert llm.base_url == "http://ollama:11434"

def test_setup_llm_openai_requires_api_key(monkeypatch: Any) -> None:
    class StubOpenAI:
        pass

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(main_mod, "OpenAIChatConnector", StubOpenAI, raising=False)

    args = _Args(llm="openai")
    bot = DummyBot()
    llm = main_mod.setup_llm(args, bot)
    assert llm is None
    assert bot._llm is None

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    llm2 = main_mod.setup_llm(args, bot)
    assert isinstance(llm2, StubOpenAI)
    assert bot._llm is llm2

def test_setup_llm_local_function_sets_callable(monkeypatch: Any) -> None:
    class StubLocalFn:
        def __init__(self, generate_fn: Any) -> None:
            self.generate_fn = generate_fn

    monkeypatch.setattr(main_mod, "LocalFunctionConnector", StubLocalFn, raising=False)
    args = _Args(llm="localfn")
    bot = DummyBot()
    llm = main_mod.setup_llm(args, bot)
    assert isinstance(llm, StubLocalFn)
    assert callable(llm.generate_fn)
    data = json.loads(llm.generate_fn("prompt"))
    assert isinstance(data, list)
    assert len(data) >= 1

def test_setup_llm_unknown_type_returns_none() -> None:
    args = _Args(llm="something-else")
    bot = DummyBot()
    llm = main_mod.setup_llm(args, bot)
    assert llm is None
    assert bot._llm is None

# --- Stubs for high-level modes ---------------------------------------------

def _install_stubs_on_module(monkeypatch: Any) -> None:
    """Install minimal stubs for SafetyConfig, BountyConfig, CyberShell to avoid heavy deps."""
    class SafetyConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class BountyConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)
            self.scope = kwargs.get("scope", [])
            self.aggressive_mode = kwargs.get("aggressive_mode", False)
            self.max_parallel_exploits = kwargs.get("max_parallel_exploits", 1)

    class CyberShell:
        def __init__(self, config: Any, doc_root: Any, planner_name: Any, scorer_name: Any, user_plugins_dir: Any) -> None:
            self.config = config
            self.doc_root = doc_root
            self.planner_name = planner_name
            self.scorer_name = scorer_name
            self.user_plugins_dir = user_plugins_dir
            self._llm = None

        def set_llm(self, llm: Any) -> None:
            self._llm = llm

        def hunt_autonomous(self, _target: Any, _bounty_config: Any) -> Any:
            return {"findings": [], "total_bounty_estimate": 0, "report": "", "metrics": {}, "evidence_summary": {}}

        def execute(self, _target: Any, _llm_step_budget: Any) -> Any:
            return {"report": "", "metrics": {}, "evidence_summary": {}}

        def execute_plugin(self, name: Any, _params: Any) -> Any:
            return _mk_result(name, success=True, details={"evidence_score": 1.0})

    monkeypatch.setattr(main_mod, "SafetyConfig", SafetyConfig, raising=False)
    monkeypatch.setattr(main_mod, "BountyConfig", BountyConfig, raising=False)
    monkeypatch.setattr(main_mod, "CyberShell", CyberShell, raising=False)

class _ArgsAll:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(
            {
                "target": "http://t",
                "doc_root": "docs",
                "planner": "depth_first",
                "scorer": "weighted_signal",
                "plugins_dir": "plugins_user",
                "output": None,
                "format": "json",
                "safe_mode": False,
                "production": False,
                "scope": None,
                "out_of_scope": None,
                "min_cvss": 4.0,
                "confidence": 0.75,
                "parallel": 2,
                "chain_exploits": False,
                "extract_data": False,
                "llm": "none",
                "llm_steps": 3,
                "verbose": False,
                "vuln_type": None,
            }
        )
        self.__dict__.update(kw)

# --- Tests: high-level modes -------------------------------------------------

def test_run_ctf_mode_smoke(monkeypatch: Any, tmp_path: Any) -> None:
    _install_stubs_on_module(monkeypatch)
    args = _ArgsAll(target="http://ctf", output=str(tmp_path / "ctf.json"), vuln_type="SQLI")
    res = main_mod.run_ctf_mode(args)
    assert isinstance(res, dict)
    assert Path(args.output).exists()

def test_run_ctf_mode_full_scan_default_filename(monkeypatch: Any) -> None:
    _install_stubs_on_module(monkeypatch)
    captured = {}

    def fake_save(_result: Any, filename: Any) -> None:
        captured["fn"] = filename

    monkeypatch.setattr(main_mod, "save_ctf_report", fake_save)
    args = _ArgsAll(target="http://ctf", output=None, vuln_type=None)
    main_mod.run_ctf_mode(args)
    assert "fn" in captured
    fn = Path(captured["fn"])
    assert fn.name.startswith("ctf_report_")
    assert fn.suffix == ".json"

def test_run_standard_mode_smoke(monkeypatch: Any, capsys: Any) -> None:
    _install_stubs_on_module(monkeypatch)
    args = _ArgsAll(target="http://t", planner="aggressive", scorer="weighted_signal", llm="none")
    main_mod.run_standard_mode(args)
    out = capsys.readouterr().out
    assert "Starting exploitation on http://t" in out

def test_run_autonomous_mode_smoke(monkeypatch: Any, capsys: Any) -> None:
    _install_stubs_on_module(monkeypatch)
    args = _ArgsAll(target="http://t", scope="a.com,b.com", out_of_scope="x.com", parallel=3, min_cvss=0.0, confidence=0.5)
    main_mod.run_autonomous_mode(args)
    out = capsys.readouterr().out
    assert "Starting autonomous hunt on http://t" in out
    assert "Aggressive mode" in out

# --- Tests: CLI main() control flow -----------------------------------------

def test_main_usage_when_no_args(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setattr(sys, "argv", ["prog"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Usage examples:" in out

def test_main_defaults_to_exploit_when_target_only(monkeypatch: Any, capsys: Any) -> None:
    _install_stubs_on_module(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["prog", "http://t"])
    try:
        main_mod.main()
    except SystemExit as e:
        if e.code not in (0,):
            raise
    out = capsys.readouterr().out
    assert "Starting exploitation on http://t" in out