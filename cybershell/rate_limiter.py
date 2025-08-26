import time
import threading
from collections import deque, defaultdict
from typing import Optional, Dict, Any, Callable
from functools import wraps
import asyncio
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Thread-safe rate limiter with multiple strategies
    Supports per-host, global, and custom rate limiting
    """
    
    def __init__(self, 
                 requests_per_second: float = 5.0,
                 burst_size: int = 10,
                 per_host_limits: Optional[Dict[str, float]] = None):
        """
        Initialize rate limiter
        
        Args:
            requests_per_second: Default global rate limit
            burst_size: Maximum burst requests allowed
            per_host_limits: Custom limits per host/domain
        """
        self.default_rps = requests_per_second
        self.burst_size = burst_size
        self.per_host_limits = per_host_limits or {}
        
        # Thread-safe request tracking
        self.lock = threading.Lock()
        self.request_times = defaultdict(deque)
        self.global_times = deque()
        
        # Statistics tracking
        self.stats = {
            'total_requests': 0,
            'total_delays': 0.0,
            'requests_blocked': 0,
            'requests_per_host': defaultdict(int)
        }
        
        # Adaptive rate limiting
        self.adaptive_mode = False
        self.response_times = deque(maxlen=100)
        
        # FIXED: Persistent async rate limiter
        self._async_limiter = None
        self._async_limiter_lock = threading.Lock()
    
    def get_async_limiter(self) -> 'AsyncRateLimiter':
        """Get or create the persistent async rate limiter"""
        if self._async_limiter is None:
            with self._async_limiter_lock:
                if self._async_limiter is None:
                    self._async_limiter = AsyncRateLimiter(self.default_rps)
        return self._async_limiter
    
    def update_async_limiter_rate(self):
        """Update async limiter rate when default_rps changes"""
        if self._async_limiter is not None:
            self._async_limiter.rate = self.default_rps
        
    def get_rate_limit(self, host: Optional[str] = None) -> float:
        """Get applicable rate limit for host"""
        if host and host in self.per_host_limits:
            return self.per_host_limits[host]
        return self.default_rps
    
    def acquire(self, host: Optional[str] = None, priority: int = 5) -> float:
        """
        Acquire permission to make a request
        
        Args:
            host: Target host for per-host limiting
            priority: Request priority (1=highest, 10=lowest)
            
        Returns:
            Time delayed in seconds
        """
        with self.lock:
            current_time = time.time()
            rate_limit = self.get_rate_limit(host)
            min_interval = 1.0 / rate_limit
            
            # Clean old timestamps
            self._clean_old_timestamps(current_time)
            
            # Calculate delay needed
            delay = 0.0
            
            # Check global rate limit
            if self.global_times:
                time_since_last = current_time - self.global_times[-1]
                if time_since_last < min_interval:
                    delay = min_interval - time_since_last
            
            # Check per-host rate limit if applicable
            if host:
                host_times = self.request_times[host]
                if host_times:
                    host_time_since = current_time - host_times[-1]
                    if host_time_since < min_interval:
                        delay = max(delay, min_interval - host_time_since)
            
            # Priority-based delay adjustment
            delay *= (priority / 5.0)
            
            # Apply delay if needed
            if delay > 0:
                time.sleep(delay)
                current_time = time.time()
                self.stats['total_delays'] += delay
            
            # Record request time
            self.global_times.append(current_time)
            if host:
                self.request_times[host].append(current_time)
                self.stats['requests_per_host'][host] += 1
            
            self.stats['total_requests'] += 1
            
            return delay
    
    def _clean_old_timestamps(self, current_time: float, window: float = 60.0):
        """Remove timestamps older than window"""
        cutoff = current_time - window
        
        # Clean global timestamps
        while self.global_times and self.global_times[0] < cutoff:
            self.global_times.popleft()
        
        # Clean per-host timestamps
        for host_times in self.request_times.values():
            while host_times and host_times[0] < cutoff:
                host_times.popleft()
    
    @contextmanager
    def bulk_operation(self, estimated_requests: int):
        """
        Context manager for bulk operations
        Pre-calculates delays to optimize throughput
        """
        if estimated_requests > self.burst_size:
            # Spread requests over time
            total_time = estimated_requests / self.default_rps
            logger.info(f"Bulk operation: {estimated_requests} requests over {total_time:.2f}s")
        
        original_rps = self.default_rps
        try:
            # Temporarily adjust rate for bulk operation
            if estimated_requests > 50:
                self.default_rps = min(self.default_rps, 2.0)  # More conservative for large bulks
                self.update_async_limiter_rate()  # Update async limiter
            yield self
        finally:
            self.default_rps = original_rps
            self.update_async_limiter_rate()  # Restore async limiter rate
    
    def adjust_adaptive(self, response_time: float, *, error_occurred: bool = False):
        """
        Adaptive rate limiting based on server response
        
        Args:
            response_time: Time taken for server response
            error_occurred: Whether an error occurred (429, timeout, etc.)
        """
        if not self.adaptive_mode:
            return
        
        self.response_times.append(response_time)
        
        if error_occurred:
            # Slow down on errors
            self.default_rps = max(1.0, self.default_rps * 0.8)
            self.update_async_limiter_rate()  # Update async limiter
            logger.warning(f"Rate limit reduced to {self.default_rps:.2f} rps due to error")
        elif len(self.response_times) >= 10:
            avg_response = sum(self.response_times) / len(self.response_times)
            
            if avg_response < 0.5:  # Server responding quickly
                self.default_rps = min(10.0, self.default_rps * 1.1)
                self.update_async_limiter_rate()  # Update async limiter
            elif avg_response > 2.0:  # Server responding slowly
                self.default_rps = max(1.0, self.default_rps * 0.9)
                self.update_async_limiter_rate()  # Update async limiter
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        with self.lock:
            return {
                **self.stats,
                'current_rps': self.default_rps,
                'adaptive_mode': self.adaptive_mode,
                'avg_delay': self.stats['total_delays'] / max(1, self.stats['total_requests'])
            }
    
    def reset_stats(self):
        """Reset statistics"""
        with self.lock:
            self.stats = {
                'total_requests': 0,
                'total_delays': 0.0,
                'requests_blocked': 0,
                'requests_per_host': defaultdict(int)
            }


class AsyncRateLimiter:
    """Async version of rate limiter for async operations"""
    
    def __init__(self, requests_per_second: float = 5.0):
        self.semaphore = asyncio.Semaphore(int(requests_per_second))
        self.rate = requests_per_second
        self.request_times = deque()
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission for async request"""
        async with self.lock:
            current = time.time()
            min_interval = 1.0 / self.rate
            
            # Clean old timestamps
            while self.request_times and self.request_times[0] < current - 60:
                self.request_times.popleft()
            
            # Calculate delay
            if self.request_times:
                elapsed = current - self.request_times[-1]
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
            
            self.request_times.append(time.time())


# Module-level cache for async limiters used by decorators
_decorator_async_limiters = {}
_decorator_limiters_lock = threading.Lock()


def rate_limited(rate_limiter: Optional[RateLimiter] = None, 
                 host_extractor: Optional[Callable] = None):
    """
    Decorator for rate limiting functions
    
    Args:
        rate_limiter: RateLimiter instance to use
        host_extractor: Function to extract host from args
    """
    def decorator(func):
        # FIXED: Store the async limiter at decoration time
        decorator_id = id(func)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal rate_limiter
            
            if rate_limiter is None:
                rate_limiter = get_global_rate_limiter()
            
            # Extract host if possible
            host = None
            if host_extractor:
                host = host_extractor(*args, **kwargs)
            elif 'url' in kwargs:
                from urllib.parse import urlparse
                host = urlparse(kwargs['url']).netloc
            elif args and isinstance(args[0], str) and args[0].startswith('http'):
                from urllib.parse import urlparse
                host = urlparse(args[0]).netloc
            
            # Apply rate limiting
            delay = rate_limiter.acquire(host=host)
            if delay > 0:
                logger.debug(f"Rate limited: delayed {delay:.3f}s for {host or 'global'}")
            
            # Execute function
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                response_time = time.time() - start_time
                
                # Adaptive adjustment
                rate_limiter.adjust_adaptive(response_time, error_occurred=False)
                
                return result
            except Exception as e:
                response_time = time.time() - start_time
                rate_limiter.adjust_adaptive(response_time, error_occurred=True)
                raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal rate_limiter
            
            if rate_limiter is None:
                rate_limiter = get_global_rate_limiter()
            
            # FIXED: Use persistent async limiter from rate_limiter instance
            async_limiter = rate_limiter.get_async_limiter()
            await async_limiter.acquire()
            return await func(*args, **kwargs)
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper
    
    return decorator


# Global rate limiter instance
_global_rate_limiter = None


def get_global_rate_limiter() -> RateLimiter:
    """Get or create global rate limiter instance"""
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = RateLimiter()
    return _global_rate_limiter


def configure_rate_limiting(config: Dict[str, Any]):
    """
    Configure global rate limiting from config
    
    Args:
        config: Configuration dictionary with rate limiting settings
    """
    global _global_rate_limiter
    
    rps = config.get('requests_per_second', 5.0)
    burst = config.get('burst_size', 10)
    per_host = config.get('per_host_limits', {})
    adaptive = config.get('adaptive_mode', False)
    
    _global_rate_limiter = RateLimiter(
        requests_per_second=rps,
        burst_size=burst,
        per_host_limits=per_host
    )
    _global_rate_limiter.adaptive_mode = adaptive
    
    logger.info(f"Rate limiting configured: {rps} rps, burst={burst}, adaptive={adaptive}")


# Integration helpers for external tools
class ToolRateLimiter:
    """Special rate limiter for external tools like Nmap and SQLMap"""
    
    def __init__(self, tool_name: str, rate_limiter: Optional[RateLimiter] = None):
        self.tool_name = tool_name
        self.rate_limiter = rate_limiter or get_global_rate_limiter()
        self.active_processes = 0
        self.lock = threading.Lock()
    
    def wrap_command(self, command: list) -> list:
        """
        Wrap tool command with rate limiting parameters
        
        Args:
            command: Tool command as list of arguments
            
        Returns:
            Modified command with rate limiting flags
        """
        tool = command[0] if command else ""
        
        if 'nmap' in tool.lower():
            # Nmap rate limiting flags
            # --max-rate <number>: Send no more than <number> packets per second
            # --scan-delay <time>: Adjust delay between probes
            max_rate = int(self.rate_limiter.default_rps * 10)  # Packets, not requests
            command.extend(['--max-rate', str(max_rate)])
            command.extend(['--scan-delay', '200ms'])  # 200ms between probes
            logger.debug(f"Nmap rate limited to {max_rate} packets/sec")
            
        elif 'sqlmap' in tool.lower():
            # SQLMap rate limiting flags
            # --delay=DELAY: Delay in seconds between HTTP requests
            delay = 1.0 / self.rate_limiter.default_rps
            command.extend(['--delay', str(delay)])
            command.extend(['--threads', '1'])  # Single thread for controlled rate
            logger.debug(f"SQLMap rate limited with {delay:.2f}s delay")
        
        return command
    
    @contextmanager
    def execute_with_limit(self, priority: int = 5):
        """Context manager for executing tool with rate limiting"""
        with self.lock:
            # Wait if too many concurrent processes
            while self.active_processes >= 2:  # Max 2 concurrent tool instances
                time.sleep(0.5)
            
            self.active_processes += 1
        
        try:
            # Apply rate limiting
            self.rate_limiter.acquire(host=f"tool:{self.tool_name}", priority=priority)
            yield
        finally:
            with self.lock:
                self.active_processes -= 1


# HTTP request wrapper for existing code
def make_rate_limited_request(request_func: Callable, *args, **kwargs):
    """
    Wrapper for making rate-limited HTTP requests
    Compatible with requests, urllib, aiohttp, etc.
    """
    rate_limiter = get_global_rate_limiter()
    
    # Extract URL for host-based limiting
    url = kwargs.get('url') or (args[0] if args else None)
    host = None
    if url:
        from urllib.parse import urlparse
        host = urlparse(url).netloc
    
    # Apply rate limiting
    rate_limiter.acquire(host=host)
    
    # Make request
    start_time = time.time()
    try:
        response = request_func(*args, **kwargs)
        response_time = time.time() - start_time
        rate_limiter.adjust_adaptive(response_time, error_occurred=False)
        return response
    except Exception as e:
        response_time = time.time() - start_time
        rate_limiter.adjust_adaptive(response_time, error_occurred=True)
        raise
