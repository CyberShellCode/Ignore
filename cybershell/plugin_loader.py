import importlib.util, sys
from pathlib import Path
from typing import Dict, Type
from .plugins import PluginBase

def load_user_plugins(dir_path: str) -> Dict[str, Type[PluginBase]]:
    registry = {}
    base = Path(dir_path)
    if not base.exists(): return registry
    for py in base.rglob('*.py'):
        spec = importlib.util.spec_from_file_location(py.stem, py)
        if not spec or not spec.loader: continue
        mod = importlib.util.module_from_spec(spec)
        sys.modules[py.stem] = mod
        spec.loader.exec_module(mod)
        for name in dir(mod):
            obj = getattr(mod, name)
            try:
                if isinstance(obj, type) and issubclass(obj, PluginBase) and obj is not PluginBase:
                    registry[obj.__name__] = obj
            except Exception:
                pass
    return registry
