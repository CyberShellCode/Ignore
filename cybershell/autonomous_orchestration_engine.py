import asyncio
import json
import time
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque
import numpy as np
from pathlib import Path
import networkx as nx
import heapq

class ExploitationState(Enum):
    """Current state of exploitation process"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PIVOTING = "pivoting"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"

class DecisionPriority(Enum):
    """Priority levels for autonomous decisions"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    OPTIONAL = 5

@dataclass
class AutonomousGoal:
    """Represents an autonomous exploitation goal"""
    id: str
    description: str
    priority: DecisionPriority
    success_criteria: Dict[str, Any]
    constraints: Dict[str, Any]
    deadline: Optional[datetime]
    dependencies: List[str]
    reward: float
    
@dataclass
class DecisionNode:
    """Node in the decision tree"""
    id: str
    state: ExploitationState
    action: str
    expected_reward: float
    cost: float
    probability_success: float
    children: List['DecisionNode'] = field(default_factory=list)
    parent: Optional['DecisionNode'] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class AutonomousOrchestrationEngine:
    """
    Implements true autonomous decision-making for exploitation
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        
        # Core components
        self.decision_maker = AutonomousDecisionMaker()
        self.goal_manager = GoalManager()
        self.state_machine = ExploitationStateMachine()
        self.resource_manager = ResourceManager()
        self.learning_engine = ReinforcementLearner()
        
        # Execution tracking
        self.current_goals: List[AutonomousGoal] = []
        self.execution_history: deque = deque(maxlen=1000)
        self.decision_tree: Optional[DecisionNode] = None
        self.exploitation_graph = nx.DiGraph()
        
        # Autonomous operation flags
        self.autonomous_mode = True
        self.pause_requested = False
        self.max_autonomous_actions = 1000
        self.actions_taken = 0
        
    def _default_config(self) -> Dict:
        """Default configuration for autonomous operation"""
        return {
            'max_parallel_exploits': 5,
            'decision_timeout': 30,  # seconds
            'learning_rate': 0.01,
            'exploration_rate': 0.2,  # epsilon for exploration vs exploitation
            'goal_reassessment_interval': 60,  # seconds
            'resource_limits': {
                'cpu_percent': 80,
                'memory_mb': 4096,
                'network_requests_per_second': 100
            },
            'safety_checks': True,
            'require_confirmation_for_critical': False
        }
    
    async def run_autonomous_exploitation(self, 
                                         target: str,
                                         objectives: List[str],
                                         constraints: Optional[Dict] = None) -> Dict:
        """Run fully autonomous exploitation"""
        
        print(f"[AUTONOMOUS] Starting autonomous exploitation of {target}")
        print(f"[AUTONOMOUS] Objectives: {objectives}")
        
        # Initialize goals from objectives
        self.current_goals = self.goal_manager.create_goals_from_objectives(
            objectives, 
            target,
            constraints or {}
        )
        
        # Initialize state machine
        self.state_machine.initialize(target)
        
        # Build initial decision tree
        self.decision_tree = await self._build_decision_tree(target)
        
        # Main autonomous loop
        results = await self._autonomous_execution_loop()
        
        # Generate comprehensive report
        report = self._generate_autonomy_report(results)
        
        return report
    
    async def _autonomous_execution_loop(self) -> List[Dict]:
        """Main autonomous execution loop"""
        
        results = []
        last_goal_reassessment = time.time()
        
        while (self.autonomous_mode and 
               not self.pause_requested and 
               self.actions_taken < self.max_autonomous_actions):
            
            # Check resource constraints
            if not self.resource_manager.check_resources_available():
                await self._handle_resource_exhaustion()
                continue
            
            # Reassess goals periodically
            if time.time() - last_goal_reassessment > self.config['goal_reassessment_interval']:
                await self._reassess_goals()
                last_goal_reassessment = time.time()
            
            # Get next action from decision maker
            decision = await self.decision_maker.get_next_decision(
                current_state=self.state_machine.current_state,
                goals=self.current_goals,
                decision_tree=self.decision_tree,
                history=self.execution_history
            )
            
            if not decision:
                print("[AUTONOMOUS] No viable decisions available")
                break
            
            # Execute decision
            result = await self._execute_decision(decision)
            results.append(result)
            
            # Update state machine
            self.state_machine.transition(result)
            
            # Learn from result
            self.learning_engine.update(decision, result)
            
            # Update decision tree based on new information
            await self._update_decision_tree(result)
            
            # Check if goals are met
            if self.goal_manager.all_goals_met(self.current_goals, results):
                print("[AUTONOMOUS] All goals achieved!")
                break
            
            self.actions_taken += 1
            
            # Brief pause to prevent overwhelming the system
            await asyncio.sleep(0.1)
        
        return results
    
    async def _build_decision_tree(self, target: str) -> DecisionNode:
        """Build decision tree for exploitation planning"""
        
        root = DecisionNode(
            id="root",
            state=ExploitationState.RECONNAISSANCE,
            action="initial_scan",
            expected_reward=0,
            cost=0,
            probability_success=1.0
        )
        
        # Build tree using breadth-first approach
        queue = [root]
        visited = set()
        
        while queue:
            node = queue.pop(0)
            
            if node.id in visited:
                continue
            visited.add(node.id)
            
            # Generate possible actions from this state
            possible_actions = await self._generate_possible_actions(
                node.state, 
                target
            )
            
            for action in possible_actions:
                child = DecisionNode(
                    id=f"{node.id}_{action['name']}",
                    state=action['next_state'],
                    action=action['name'],
                    expected_reward=action['reward'],
                    cost=action['cost'],
                    probability_success=action['probability'],
                    parent=node
                )
                
                node.children.append(child)
                
                # Add to queue if not terminal state
                if not self._is_terminal_state(child.state):
                    queue.append(child)
        
        return root
    
    async def _generate_possible_actions(self, 
                                        state: ExploitationState,
                                        target: str) -> List[Dict]:
        """Generate possible actions from current state"""
        
        actions = []
        
        if state == ExploitationState.RECONNAISSANCE:
            actions = [
                {
                    'name': 'port_scan',
                    'next_state': ExploitationState.VULNERABILITY_DISCOVERY,
                    'reward': 10,
                    'cost': 1,
                    'probability': 0.95
                },
                {
                    'name': 'service_enumeration',
                    'next_state': ExploitationState.VULNERABILITY_DISCOVERY,
                    'reward': 15,
                    'cost': 2,
                    'probability': 0.90
                }
            ]
        
        elif state == ExploitationState.VULNERABILITY_DISCOVERY:
            actions = [
                {
                    'name': 'vulnerability_scan',
                    'next_state': ExploitationState.EXPLOITATION,
                    'reward': 25,
                    'cost': 5,
                    'probability': 0.80
                },
                {
                    'name': 'manual_testing',
                    'next_state': ExploitationState.EXPLOITATION,
                    'reward': 30,
                    'cost': 10,
                    'probability': 0.70
                }
            ]
        
        elif state == ExploitationState.EXPLOITATION:
            actions = [
                {
                    'name': 'exploit_vulnerability',
                    'next_state': ExploitationState.POST_EXPLOITATION,
                    'reward': 100,
                    'cost': 20,
                    'probability': 0.60
                },
                {
                    'name': 'chain_exploits',
                    'next_state': ExploitationState.POST_EXPLOITATION,
                    'reward': 150,
                    'cost': 30,
                    'probability': 0.40
                }
            ]
        
        elif state == ExploitationState.POST_EXPLOITATION:
            actions = [
                {
                    'name': 'establish_persistence',
                    'next_state': ExploitationState.PERSISTENCE,
                    'reward': 50,
                    'cost': 10,
                    'probability': 0.70
                },
                {
                    'name': 'lateral_movement',
                    'next_state': ExploitationState.PIVOTING,
                    'reward': 75,
                    'cost': 15,
                    'probability': 0.65
                }
            ]
        
        return actions
    
    def _is_terminal_state(self, state: ExploitationState) -> bool:
        """Check if state is terminal"""
        return state in [ExploitationState.CLEANUP, ExploitationState.EXFILTRATION]
    
    async def _execute_decision(self, decision: Dict) -> Dict:
        """Execute autonomous decision"""
        
        start_time = time.time()
        
        print(f"[AUTONOMOUS] Executing: {decision['action']} (Priority: {decision['priority']})")
        
        try:
            # Route to appropriate execution handler
            if decision['action'].startswith('scan'):
                result = await self._execute_scan(decision)
            elif decision['action'].startswith('exploit'):
                result = await self._execute_exploit(decision)
            elif decision['action'].startswith('pivot'):
                result = await self._execute_pivot(decision)
            else:
                result = await self._execute_generic_action(decision)
            
            execution_time = time.time() - start_time
            
            # Record execution
            self.execution_history.append({
                'timestamp': datetime.now(),
                'decision': decision,
                'result': result,
                'execution_time': execution_time
            })
            
            # Update resource usage
            self.resource_manager.update_usage(decision['action'], execution_time)
            
            return {
                'success': result.get('success', False),
                'action': decision['action'],
                'state_before': self.state_machine.current_state,
                'state_after': result.get('next_state'),
                'data': result.get('data', {}),
                'execution_time': execution_time
            }
            
        except Exception as e:
            print(f"[AUTONOMOUS] Error executing {decision['action']}: {e}")
            return {
                'success': False,
                'action': decision['action'],
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    async def _execute_scan(self, decision: Dict) -> Dict:
        """Execute scanning action"""
        # Simulate scan execution
        await asyncio.sleep(np.random.uniform(1, 5))
        
        return {
            'success': np.random.random() > 0.2,
            'next_state': ExploitationState.VULNERABILITY_DISCOVERY,
            'data': {
                'open_ports': [80, 443, 22, 3306],
                'services': ['http', 'https', 'ssh', 'mysql']
            }
        }
    
    async def _execute_exploit(self, decision: Dict) -> Dict:
        """Execute exploitation action"""
        # Simulate exploit execution
        await asyncio.sleep(np.random.uniform(2, 10))
        
        success = np.random.random() > 0.4
        
        return {
            'success': success,
            'next_state': ExploitationState.POST_EXPLOITATION if success else ExploitationState.EXPLOITATION,
            'data': {
                'vulnerability_exploited': decision.get('vulnerability', 'unknown'),
                'access_level': 'user' if success else 'none'
            }
        }
    
    async def _execute_pivot(self, decision: Dict) -> Dict:
        """Execute pivoting action"""
        # Simulate pivot execution
        await asyncio.sleep(np.random.uniform(3, 8))
        
        return {
            'success': np.random.random() > 0.5,
            'next_state': ExploitationState.EXPLOITATION,
            'data': {
                'new_targets': ['192.168.1.10', '192.168.1.11'],
                'network_segment': 'internal'
            }
        }
    
    async def _execute_generic_action(self, decision: Dict) -> Dict:
        """Execute generic action"""
        await asyncio.sleep(np.random.uniform(1, 3))
        
        return {
            'success': np.random.random() > 0.3,
            'next_state': self.state_machine.current_state,
            'data': {}
        }
    
    async def _reassess_goals(self):
        """Reassess and reprioritize goals"""
        
        print("[AUTONOMOUS] Reassessing goals...")
        
        # Evaluate progress on current goals
        for goal in self.current_goals:
            progress = self.goal_manager.evaluate_progress(goal, self.execution_history)
            
            # Adjust priority based on progress
            if progress < 0.2 and goal.deadline:
                time_remaining = (goal.deadline - datetime.now()).total_seconds()
                if time_remaining < 3600:  # Less than 1 hour
                    goal.priority = DecisionPriority.CRITICAL
        
        # Sort goals by priority
        self.current_goals.sort(key=lambda g: g.priority.value)
    
    async def _update_decision_tree(self, result: Dict):
        """Update decision tree based on execution results"""
        
        if not result.get('success'):
            # Reduce probability of failed action path
            self._update_path_probability(
                self.decision_tree,
                result['action'],
                factor=0.8
            )
        else:
            # Increase probability of successful path
            self._update_path_probability(
                self.decision_tree,
                result['action'],
                factor=1.2
            )
    
    def _update_path_probability(self, node: DecisionNode, action: str, factor: float):
        """Update probability along a path in decision tree"""
        
        if node.action == action:
            node.probability_success = min(1.0, node.probability_success * factor)
            return
        
        for child in node.children:
            self._update_path_probability(child, action, factor)
    
    async def _handle_resource_exhaustion(self):
        """Handle resource exhaustion"""
        
        print("[AUTONOMOUS] Resource limits reached, throttling...")
        
        # Wait for resources to become available
        await asyncio.sleep(5)
        
        # Reduce parallelism
        self.config['max_parallel_exploits'] = max(1, self.config['max_parallel_exploits'] - 1)
    
    def _generate_autonomy_report(self, results: List[Dict]) -> Dict:
        """Generate comprehensive autonomy report"""
        
        successful_actions = [r for r in results if r.get('success')]
        
        return {
            'summary': {
                'total_actions': len(results),
                'successful_actions': len(successful_actions),
                'success_rate': len(successful_actions) / len(results) if results else 0,
                'goals_achieved': self.goal_manager.count_achieved_goals(self.current_goals, results),
                'total_goals': len(self.current_goals),
                'autonomous_duration': sum(r.get('execution_time', 0) for r in results)
            },
            'execution_path': [
                {
                    'action': r['action'],
                    'success': r.get('success'),
                    'state': r.get('state_after')
                }
                for r in results
            ],
            'goals_status': [
                {
                    'goal': goal.description,
                    'achieved': self.goal_manager.is_goal_met(goal, results),
                    'progress': self.goal_manager.evaluate_progress(goal, self.execution_history)
                }
                for goal in self.current_goals
            ],
            'resource_usage': self.resource_manager.get_usage_report(),
            'learning_insights': self.learning_engine.get_insights(),
            'decision_tree_stats': self._analyze_decision_tree()
        }
    
    def _analyze_decision_tree(self) -> Dict:
        """Analyze decision tree statistics"""
        
        if not self.decision_tree:
            return {}
        
        total_nodes = self._count_nodes(self.decision_tree)
        max_depth = self._get_max_depth(self.decision_tree)
        
        return {
            'total_nodes': total_nodes,
            'max_depth': max_depth,
            'average_branching_factor': self._get_avg_branching(self.decision_tree)
        }
    
    def _count_nodes(self, node: DecisionNode) -> int:
        """Count total nodes in tree"""
        count = 1
        for child in node.children:
            count += self._count_nodes(child)
        return count
    
    def _get_max_depth(self, node: DecisionNode, depth: int = 0) -> int:
        """Get maximum depth of tree"""
        if not node.children:
            return depth
        return max(self._get_max_depth(child, depth + 1) for child in node.children)
    
    def _get_avg_branching(self, node: DecisionNode) -> float:
        """Get average branching factor"""
        total_children = 0
        total_non_leaf = 0
        
        queue = [node]
        while queue:
            current = queue.pop(0)
            if current.children:
                total_children += len(current.children)
                total_non_leaf += 1
                queue.extend(current.children)
        
        return total_children / total_non_leaf if total_non_leaf > 0 else 0


class AutonomousDecisionMaker:
    """Makes autonomous decisions based on current context"""
    
    def __init__(self):
        self.decision_history = []
        self.decision_cache = {}
        
    async def get_next_decision(self, 
                               current_state: ExploitationState,
                               goals: List[AutonomousGoal],
                               decision_tree: DecisionNode,
                               history: deque) -> Optional[Dict]:
        """Get next autonomous decision"""
        
        # Find highest priority unmet goal
        priority_goal = self._get_priority_goal(goals, history)
        
        if not priority_goal:
            return None
        
        # Find best path in decision tree
        best_path = self._find_best_path(
            decision_tree, 
            current_state, 
            priority_goal
        )
        
        if not best_path:
            return None
        
        # Get next action from path
        next_action = best_path[0] if best_path else None
        
        if not next_action:
            return None
        
        return {
            'action': next_action.action,
            'priority': priority_goal.priority,
            'expected_reward': next_action.expected_reward,
            'probability_success': next_action.probability_success,
            'goal': priority_goal.id
        }
    
    def _get_priority_goal(self, goals: List[AutonomousGoal], history: deque) -> Optional[AutonomousGoal]:
        """Get highest priority unmet goal"""
        
        for goal in sorted(goals, key=lambda g: g.priority.value):
            if not self._is_goal_met(goal, history):
                return goal
        return None
    
    def _is_goal_met(self, goal: AutonomousGoal, history: deque) -> bool:
        """Check if goal is met"""
        # Simplified check - would need actual criteria evaluation
        for entry in history:
            if entry.get('result', {}).get('goal_id') == goal.id:
                return True
        return False
    
    def _find_best_path(self, 
                       tree: DecisionNode,
                       current_state: ExploitationState,
                       goal: AutonomousGoal) -> List[DecisionNode]:
        """Find best path to achieve goal"""
        
        # Use A* search to find optimal path
        start_node = self._find_state_node(tree, current_state)
        if not start_node:
            return []
        
        # Priority queue: (cost, path)
        pq = [(0, [start_node])]
        visited = set()
        
        while pq:
            cost, path = heapq.heappop(pq)
            current = path[-1]
            
            if current.id in visited:
                continue
            visited.add(current.id)
            
            # Check if goal is achieved
            if self._achieves_goal(current, goal):
                return path[1:]  # Exclude start node
            
            # Explore children
            for child in current.children:
                if child.id not in visited:
                    new_cost = cost + child.cost
                    new_path = path + [child]
                    priority = new_cost - child.expected_reward * child.probability_success
                    heapq.heappush(pq, (priority, new_path))
        
        return []
    
    def _find_state_node(self, node: DecisionNode, state: ExploitationState) -> Optional[DecisionNode]:
        """Find node with given state"""
        if node.state == state:
            return node
        
        for child in node.children:
            result = self._find_state_node(child, state)
            if result:
                return result
        return None
    
    def _achieves_goal(self, node: DecisionNode, goal: AutonomousGoal) -> bool:
        """Check if node achieves goal"""
        # Simplified check - would need actual goal evaluation
        return node.expected_reward >= goal.reward * 0.8


class GoalManager:
    """Manages autonomous exploitation goals"""
    
    def create_goals_from_objectives(self, 
                                    objectives: List[str],
                                    target: str,
                                    constraints: Dict) -> List[AutonomousGoal]:
        """Create goals from high-level objectives"""
        
        goals = []
        
        for i, objective in enumerate(objectives):
            if 'flag' in objective.lower() or 'ctf' in objective.lower():
                goal = AutonomousGoal(
                    id=f"goal_{i}_ctf",
                    description=f"Capture flag from {target}",
                    priority=DecisionPriority.CRITICAL,
                    success_criteria={'flag_captured': True},
                    constraints=constraints,
                    deadline=datetime.now() + timedelta(hours=2),
                    dependencies=[],
                    reward=1000
                )
            elif 'root' in objective.lower() or 'admin' in objective.lower():
                goal = AutonomousGoal(
                    id=f"goal_{i}_privesc",
                    description=f"Achieve root/admin access on {target}",
                    priority=DecisionPriority.HIGH,
                    success_criteria={'access_level': 'root'},
                    constraints=constraints,
                    deadline=None,
                    dependencies=[],
                    reward=800
                )
            elif 'data' in objective.lower() or 'exfil' in objective.lower():
                goal = AutonomousGoal(
                    id=f"goal_{i}_exfil",
                    description=f"Exfiltrate sensitive data from {target}",
                    priority=DecisionPriority.MEDIUM,
                    success_criteria={'data_exfiltrated': True},
                    constraints=constraints,
                    deadline=None,
                    dependencies=[f"goal_{i}_privesc"],
                    reward=600
                )
            else:
                goal = AutonomousGoal(
                    id=f"goal_{i}_generic",
                    description=objective,
                    priority=DecisionPriority.MEDIUM,
                    success_criteria={},
                    constraints=constraints,
                    deadline=None,
                    dependencies=[],
                    reward=500
                )
            
            goals.append(goal)
        
        return goals
    
    def all_goals_met(self, goals: List[AutonomousGoal], results: List[Dict]) -> bool:
        """Check if all goals are met"""
        return all(self.is_goal_met(goal, results) for goal in goals)
    
    def is_goal_met(self, goal: AutonomousGoal, results: List[Dict]) -> bool:
        """Check if specific goal is met"""
        for criteria_key, criteria_value in goal.success_criteria.items():
            met = False
            for result in results:
                if result.get('data', {}).get(criteria_key) == criteria_value:
                    met = True
                    break
            if not met:
                return False
        return True
    
    def evaluate_progress(self, goal: AutonomousGoal, history: deque) -> float:
        """Evaluate progress towards goal (0-1)"""
        
        # Count criteria met
        criteria_met = 0
        total_criteria = len(goal.success_criteria)
        
        if total_criteria == 0:
            return 0.0
        
        for criteria_key, criteria_value in goal.success_criteria.items():
            for entry in history:
                if entry.get('result', {}).get('data', {}).get(criteria_key) == criteria_value:
                    criteria_met += 1
                    break
        
        return criteria_met / total_criteria
    
    def count_achieved_goals(self, goals: List[AutonomousGoal], results: List[Dict]) -> int:
        """Count number of achieved goals"""
        return sum(1 for goal in goals if self.is_goal_met(goal, results))


class ExploitationStateMachine:
    """Manages exploitation state transitions"""
    
    def __init__(self):
        self.current_state = ExploitationState.RECONNAISSANCE
        self.state_history = []
        self.transition_rules = self._define_transitions()
        
    def _define_transitions(self) -> Dict:
        """Define valid state transitions"""
        return {
            ExploitationState.RECONNAISSANCE: [
                ExploitationState.VULNERABILITY_DISCOVERY
            ],
            ExploitationState.VULNERABILITY_DISCOVERY: [
                ExploitationState.EXPLOITATION,
                ExploitationState.RECONNAISSANCE
            ],
            ExploitationState.EXPLOITATION: [
                ExploitationState.POST_EXPLOITATION,
                ExploitationState.VULNERABILITY_DISCOVERY
            ],
            ExploitationState.POST_EXPLOITATION: [
                ExploitationState.PERSISTENCE,
                ExploitationState.PIVOTING,
                ExploitationState.EXFILTRATION
            ],
            ExploitationState.PIVOTING: [
                ExploitationState.RECONNAISSANCE,
                ExploitationState.EXPLOITATION
            ],
            ExploitationState.PERSISTENCE: [
                ExploitationState.EXFILTRATION,
                ExploitationState.CLEANUP
            ],
            ExploitationState.EXFILTRATION: [
                ExploitationState.CLEANUP
            ],
            ExploitationState.CLEANUP: []
        }
    
    def initialize(self, target: str):
        """Initialize state machine for target"""
        self.current_state = ExploitationState.RECONNAISSANCE
        self.state_history = [{
            'state': self.current_state,
            'timestamp': datetime.now(),
            'target': target
        }]
    
    def transition(self, result: Dict):
        """Transition to new state based on result"""
        
        new_state = result.get('state_after')
        
        if new_state and self.is_valid_transition(self.current_state, new_state):
            self.current_state = new_state
            self.state_history.append({
                'state': new_state,
                'timestamp': datetime.now(),
                'trigger': result.get('action')
            })
    
    def is_valid_transition(self, from_state: ExploitationState, to_state: ExploitationState) -> bool:
        """Check if transition is valid"""
        return to_state in self.transition_rules.get(from_state, [])


class ResourceManager:
    """Manages resource allocation and monitoring"""
    
    def __init__(self):
        self.resource_usage = {
            'cpu': [],
            'memory': [],
            'network': []
        }
        self.limits = {}
        
    def check_resources_available(self) -> bool:
        """Check if resources are available"""
        # Simplified check - would use actual system monitoring
        return True
    
    def update_usage(self, action: str, duration: float):
        """Update resource usage statistics"""
        
        # Estimate resource usage based on action
        cpu_usage = np.random.uniform(10, 50)
        memory_usage = np.random.uniform(100, 500)
        network_requests = np.random.randint(10, 100)
        
        self.resource_usage['cpu'].append(cpu_usage)
        self.resource_usage['memory'].append(memory_usage)
        self.resource_usage['network'].append(network_requests)
    
    def get_usage_report(self) -> Dict:
        """Get resource usage report"""
        
        return {
            'average_cpu': np.mean(self.resource_usage['cpu']) if self.resource_usage['cpu'] else 0,
            'peak_memory': max(self.resource_usage['memory']) if self.resource_usage['memory'] else 0,
            'total_network_requests': sum(self.resource_usage['network'])
        }


class ReinforcementLearner:
    """Reinforcement learning for improving autonomous decisions"""
    
    def __init__(self, learning_rate: float = 0.01):
        self.learning_rate = learning_rate
        self.q_table = {}  # State-action value table
        self.experience_replay = deque(maxlen=1000)
        
    def update(self, decision: Dict, result: Dict):
        """Update Q-values based on result"""
        
        state_action = f"{decision.get('state', 'unknown')}_{decision['action']}"
        
        # Calculate reward
        reward = self._calculate_reward(result)
        
        # Update Q-value
        if state_action not in self.q_table:
            self.q_table[state_action] = 0
        
        # Simple Q-learning update
        old_value = self.q_table[state_action]
        self.q_table[state_action] = old_value + self.learning_rate * (reward - old_value)
        
        # Store experience
        self.experience_replay.append({
            'decision': decision,
            'result': result,
            'reward': reward
        })
    
    def _calculate_reward(self, result: Dict) -> float:
        """Calculate reward for action result"""
        
        reward = 0
        
        if result.get('success'):
            reward += 100
        else:
            reward -= 10
        
        # Bonus for state progression
        if result.get('state_after') != result.get('state_before'):
            reward += 50
        
        # Penalty for long execution time
        execution_time = result.get('execution_time', 0)
        if execution_time > 30:
            reward -= 20
        
        return reward
    
    def get_insights(self) -> Dict:
        """Get learning insights"""
        
        if not self.q_table:
            return {'message': 'No learning data yet'}
        
        best_actions = sorted(self.q_table.items(), key=lambda x: x[1], reverse=True)[:5]
        worst_actions = sorted(self.q_table.items(), key=lambda x: x[1])[:5]
        
        return {
            'total_experiences': len(self.experience_replay),
            'best_state_actions': best_actions,
            'worst_state_actions': worst_actions,
            'average_q_value': np.mean(list(self.q_table.values()))
        }
