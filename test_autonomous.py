# Create a test script: test_autonomous.py
from cybershell.orchestrator import Orchestrator
from cybershell.autonomous_orchestration_engine import AutonomousOrchestrationEngine
import asyncio

async def test_autonomous():
    # Initialize the autonomous engine
    engine = AutonomousOrchestrationEngine()
    
    # Set scope for safety
    engine.set_scope(
        allowed=['testphp.vulnweb.com'],
        excluded=[]
    )
    
    # Run autonomous exploitation
    result = await engine.run_autonomous_exploitation(
        target='http://testphp.vulnweb.com',
        objectives=['Find and exploit SQL injection', 'Find XSS vulnerabilities'],
        constraints={'max_time': 300}  # 5 minutes
    )
    
    print(json.dumps(result, indent=2))

# Run it
asyncio.run(test_autonomous())
