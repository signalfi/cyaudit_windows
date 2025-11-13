"""Security assessment module - performs Windows security audits"""

import subprocess
import logging
import platform
import socket
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


logger = logging.getLogger(__name__)


class SecurityAssessment:
    """Perform comprehensive Windows security assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.assessment_config = config.get('assessment', {})
        self.output_dir = Path(config.get('output_directory', 'assessments'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scripts_dir = Path(__file__).parent.parent / 'scripts'
    
    def run(self) -> List[Dict[str, Any]]:
        """Run complete security assessment"""
        assessment_data = []
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Collect system information
        if self.assessment_config.get('include_system_info', True):
            logger.info("Collecting system information...")
            assessment_data.extend(self._collect_system_info(timestamp))
        
        # Collect user information
        if self.assessment_config.get('include_users', True):
            logger.info("Collecting user information...")
            assessment_data.extend(self._collect_users(timestamp))
        
        # Collect group information
        if self.assessment_config.get('include_groups', True):
            logger.info("Collecting group information...")
            assessment_data.extend(self._collect_groups(timestamp))
        
        # Collect service information
        if self.assessment_config.get('include_services', True):
            logger.info("Collecting service information...")
            assessment_data.extend(self._collect_services(timestamp))
        
        # Collect process information
        if self.assessment_config.get('include_processes', True):
            logger.info("Collecting process information...")
            assessment_data.extend(self._collect_processes(timestamp))
        
        # Collect network information
        if self.assessment_config.get('include_network', True):
            logger.info("Collecting network information...")
            assessment_data.extend(self._collect_network(timestamp))
        
        # Collect security policies
        if self.assessment_config.get('include_security_policies', True):
            logger.info("Collecting security policies...")
            assessment_data.extend(self._collect_security_policies(timestamp))
        
        # Collect registry security settings
        if self.assessment_config.get('include_registry', True):
            logger.info("Collecting registry security settings...")
            assessment_data.extend(self._collect_registry_security(timestamp))
        
        # Collect installed software
        if self.assessment_config.get('include_installed_software', True):
            logger.info("Collecting installed software...")
            assessment_data.extend(self._collect_installed_software(timestamp))
        
        return assessment_data
    
    def _collect_system_info(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect system information"""
        try:
            data = {
                'event_type': 'system_info',
                'timestamp': timestamp,
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'platform_version': platform.version(),
                'platform_release': platform.release(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
            }
            
            # Try to get additional Windows-specific info
            if platform.system() == 'Windows':
                try:
                    result = self._run_powershell('Get-ComputerInfo | ConvertTo-Json -Depth 3')
                    if result:
                        computer_info = json.loads(result)
                        data['computer_info'] = computer_info
                except Exception as e:
                    logger.debug(f"Could not get extended computer info: {e}")
            
            return [data]
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return []
    
    def _collect_users(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect user account information"""
        users = []
        try:
            if platform.system() == 'Windows':
                result = self._run_powershell(
                    'Get-LocalUser | Select-Object Name, Enabled, Description, '
                    'LastLogon, PasswordLastSet, PasswordRequired | ConvertTo-Json'
                )
                if result:
                    user_data = json.loads(result)
                    if isinstance(user_data, dict):
                        user_data = [user_data]
                    
                    for user in user_data:
                        users.append({
                            'event_type': 'user',
                            'timestamp': timestamp,
                            'hostname': socket.gethostname(),
                            'user_name': user.get('Name'),
                            'enabled': user.get('Enabled'),
                            'description': user.get('Description'),
                            'last_logon': user.get('LastLogon'),
                            'password_last_set': user.get('PasswordLastSet'),
                            'password_required': user.get('PasswordRequired')
                        })
        except Exception as e:
            logger.error(f"Error collecting users: {e}")
        
        return users
    
    def _collect_groups(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect group information"""
        groups = []
        try:
            if platform.system() == 'Windows':
                result = self._run_powershell(
                    'Get-LocalGroup | Select-Object Name, Description | ConvertTo-Json'
                )
                if result:
                    group_data = json.loads(result)
                    if isinstance(group_data, dict):
                        group_data = [group_data]
                    
                    for group in group_data:
                        groups.append({
                            'event_type': 'group',
                            'timestamp': timestamp,
                            'hostname': socket.gethostname(),
                            'group_name': group.get('Name'),
                            'description': group.get('Description')
                        })
        except Exception as e:
            logger.error(f"Error collecting groups: {e}")
        
        return groups
    
    def _collect_services(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect Windows service information"""
        services = []
        try:
            if platform.system() == 'Windows':
                result = self._run_powershell(
                    'Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json'
                )
                if result:
                    service_data = json.loads(result)
                    if isinstance(service_data, dict):
                        service_data = [service_data]
                    
                    for service in service_data:
                        services.append({
                            'event_type': 'service',
                            'timestamp': timestamp,
                            'hostname': socket.gethostname(),
                            'service_name': service.get('Name'),
                            'display_name': service.get('DisplayName'),
                            'status': service.get('Status'),
                            'start_type': service.get('StartType')
                        })
        except Exception as e:
            logger.error(f"Error collecting services: {e}")
        
        return services
    
    def _collect_processes(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect running process information"""
        processes = []
        try:
            if platform.system() == 'Windows':
                result = self._run_powershell(
                    'Get-Process | Select-Object Id, ProcessName, Path, Company | ConvertTo-Json'
                )
                if result:
                    process_data = json.loads(result)
                    if isinstance(process_data, dict):
                        process_data = [process_data]
                    
                    for process in process_data:
                        processes.append({
                            'event_type': 'process',
                            'timestamp': timestamp,
                            'hostname': socket.gethostname(),
                            'process_id': process.get('Id'),
                            'process_name': process.get('ProcessName'),
                            'path': process.get('Path'),
                            'company': process.get('Company')
                        })
        except Exception as e:
            logger.error(f"Error collecting processes: {e}")
        
        return processes
    
    def _collect_network(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect network configuration"""
        network_info = []
        try:
            if platform.system() == 'Windows':
                result = self._run_powershell(
                    'Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed | ConvertTo-Json'
                )
                if result:
                    adapter_data = json.loads(result)
                    if isinstance(adapter_data, dict):
                        adapter_data = [adapter_data]
                    
                    for adapter in adapter_data:
                        network_info.append({
                            'event_type': 'network_adapter',
                            'timestamp': timestamp,
                            'hostname': socket.gethostname(),
                            'adapter_name': adapter.get('Name'),
                            'status': adapter.get('Status'),
                            'mac_address': adapter.get('MacAddress'),
                            'link_speed': adapter.get('LinkSpeed')
                        })
        except Exception as e:
            logger.error(f"Error collecting network info: {e}")
        
        return network_info
    
    def _collect_security_policies(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect security policy settings"""
        policies = []
        try:
            if platform.system() == 'Windows':
                # Get audit policy
                result = self._run_powershell(
                    'auditpol /get /category:* | Out-String'
                )
                if result:
                    policies.append({
                        'event_type': 'audit_policy',
                        'timestamp': timestamp,
                        'hostname': socket.gethostname(),
                        'policy_data': result
                    })
        except Exception as e:
            logger.error(f"Error collecting security policies: {e}")
        
        return policies
    
    def _collect_registry_security(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect security-related registry settings"""
        registry_data = []
        try:
            if platform.system() == 'Windows':
                # Common security-related registry keys
                registry_keys = [
                    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                    'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
                    'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'
                ]
                
                for key in registry_keys:
                    try:
                        result = self._run_powershell(
                            f'Get-ItemProperty -Path "{key}" | ConvertTo-Json -Depth 2'
                        )
                        if result:
                            reg_info = json.loads(result)
                            registry_data.append({
                                'event_type': 'registry_security',
                                'timestamp': timestamp,
                                'hostname': socket.gethostname(),
                                'registry_key': key,
                                'values': reg_info
                            })
                    except Exception as e:
                        logger.debug(f"Could not read registry key {key}: {e}")
        except Exception as e:
            logger.error(f"Error collecting registry security: {e}")
        
        return registry_data
    
    def _collect_installed_software(self, timestamp: str) -> List[Dict[str, Any]]:
        """Collect installed software information"""
        software = []
        try:
            if platform.system() == 'Windows':
                result = self._run_powershell(
                    'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | '
                    'Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | '
                    'Where-Object {$_.DisplayName} | ConvertTo-Json'
                )
                if result:
                    software_data = json.loads(result)
                    if isinstance(software_data, dict):
                        software_data = [software_data]
                    
                    for app in software_data:
                        software.append({
                            'event_type': 'installed_software',
                            'timestamp': timestamp,
                            'hostname': socket.gethostname(),
                            'software_name': app.get('DisplayName'),
                            'version': app.get('DisplayVersion'),
                            'publisher': app.get('Publisher'),
                            'install_date': app.get('InstallDate')
                        })
        except Exception as e:
            logger.error(f"Error collecting installed software: {e}")
        
        return software
    
    def _run_powershell(self, command: str, timeout: int = 30) -> str:
        """Execute PowerShell command and return output"""
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', command],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.warning(f"PowerShell command timed out: {command[:50]}...")
            return ""
        except subprocess.CalledProcessError as e:
            logger.warning(f"PowerShell command failed: {e}")
            return ""
        except Exception as e:
            logger.error(f"Error running PowerShell command: {e}")
            return ""
