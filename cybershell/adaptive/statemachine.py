import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional
@dataclass
class State:
    """A simple FSM state with optional enter/exit hooks."""
    name: str
    on_enter: Optional[Callable[[], None]] = None
    on_exit: Optional[Callable[[], None]] = None
class SimpleStateMachine:
    def __init__(self, initial: str):
        self.state = initial
        self.states: Dict[str, State] = {}
        self.transitions: Dict[tuple, str] = {}
    def add_state(self, state: State):
        self.states[state.name] = state
    def add_transition(self, src: str, event: str, dst: str):
        self.transitions[(src, event)] = dst
    def send(self, event: str):
        key = (self.state, event)
        if key not in self.transitions: return False
        self.states[self.state].on_exit()
        self.state = self.transitions[key]
        self.states[self.state].on_enter()
        return True
def retry(func, attempts=3, base_delay=0.5, factor=2.0):
    def wrapper(*args, **kwargs):
        delay = base_delay; last_exc = None
        for _ in range(attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exc = e; time.sleep(delay); delay *= factor
        raise last_exc
    return wrapper
