"""Splunk Universal Forwarder integration module"""

import logging
import subprocess
from pathlib import Path
from typing import Dict, Any


logger = logging.getLogger(__name__)


class SplunkForwarder:
    """Integrate with Splunk Universal Forwarder"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.splunk_config = config.get('splunk', {})
        self.forwarder_path = Path(self.splunk_config.get('forwarder_path', 'C:\\Program Files\\SplunkUniversalForwarder'))
        self.splunk_bin = self.forwarder_path / 'bin' / 'splunk.exe'
    
    def forward(self, ndjson_file: Path):
        """Configure Splunk Universal Forwarder to monitor the assessment file"""
        if not self.splunk_config.get('enabled', False):
            logger.info("Splunk forwarding is disabled")
            return
        
        try:
            # Check if Splunk Universal Forwarder is installed
            if not self.splunk_bin.exists():
                logger.warning(f"Splunk Universal Forwarder not found at {self.splunk_bin}")
                logger.info("Please install Splunk Universal Forwarder to enable automatic forwarding")
                return
            
            # Add monitor for the output directory if configured
            monitor_path = self.splunk_config.get('monitor_path')
            if monitor_path:
                self._add_monitor(monitor_path)
            else:
                # Monitor the specific file
                self._add_monitor(str(ndjson_file))
            
            logger.info("Splunk forwarding configured successfully")
            
        except Exception as e:
            logger.error(f"Error configuring Splunk forwarding: {e}")
            raise
    
    def _add_monitor(self, path: str):
        """Add a monitor to Splunk Universal Forwarder"""
        try:
            sourcetype = self.splunk_config.get('sourcetype', 'cyaudit:windows:assessment')
            
            # Check if monitor already exists
            check_cmd = [
                str(self.splunk_bin),
                'list', 'monitor',
                '-auth', 'admin:changeme'  # Default credentials, should be configured
            ]
            
            logger.info(f"Adding Splunk monitor for: {path}")
            
            # Add monitor command
            add_cmd = [
                str(self.splunk_bin),
                'add', 'monitor',
                path,
                '-sourcetype', sourcetype,
                '-auth', 'admin:changeme'
            ]
            
            result = subprocess.run(
                add_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"Monitor added successfully: {path}")
            else:
                # Monitor might already exist
                if "already exists" in result.stderr.lower():
                    logger.info(f"Monitor already exists: {path}")
                else:
                    logger.warning(f"Could not add monitor: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            logger.warning("Splunk command timed out")
        except Exception as e:
            logger.error(f"Error adding Splunk monitor: {e}")
    
    def is_installed(self) -> bool:
        """Check if Splunk Universal Forwarder is installed"""
        return self.splunk_bin.exists()
    
    def get_status(self) -> str:
        """Get Splunk Universal Forwarder status"""
        try:
            if not self.is_installed():
                return "Not installed"
            
            result = subprocess.run(
                [str(self.splunk_bin), 'status'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return result.stdout.strip() if result.returncode == 0 else "Unknown"
            
        except Exception as e:
            logger.error(f"Error checking Splunk status: {e}")
            return "Error"
