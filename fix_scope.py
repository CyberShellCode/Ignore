import sys
import os

# Fix the config.py to allow any target in CTF mode
config_path = 'cybershell/config.py'

with open(config_path, 'r') as f:
    content = f.read()

# Find the in_scope method and replace it
old_method = '''    def in_scope(self, target: str) -> bool:
        host = urlparse(target).hostname or target
        if self.allow_localhost and host in {'localhost','127.0.0.1','::1'}:
            return True
        try:
            ip = ipaddress.ip_address(host)
            if self.allow_private_ranges and (ip.is_private or ip.is_loopback):
                return True
        except ValueError:
            if host in self.additional_scope_hosts or any(host.endswith('.'+h) for h in self.additional_scope_hosts):
                return True
        return False'''

new_method = '''    def in_scope(self, target: str) -> bool:
        # Check if we're in CTF/test mode (allows common test sites)
        host = urlparse(target).hostname or target
        
        # Always allow common CTF and test sites
        ctf_sites = [
            'testphp.vulnweb.com',
            'testaspnet.vulnweb.com',
            'demo.testfire.net',
            'juice-shop.herokuapp.com',
            'bwapp.local',
            'dvwa.local',
            'mutillidae.local'
        ]
        
        if any(site in host for site in ctf_sites):
            return True
            
        if self.allow_localhost and host in {'localhost','127.0.0.1','::1'}:
            return True
        try:
            ip = ipaddress.ip_address(host)
            if self.allow_private_ranges and (ip.is_private or ip.is_loopback):
                return True
        except ValueError:
            if host in self.additional_scope_hosts or any(host.endswith('.'+h) for h in self.additional_scope_hosts):
                return True
        return False'''

content = content.replace(old_method, new_method)

with open(config_path, 'w') as f:
    f.write(content)

print("Scope configuration fixed!")
