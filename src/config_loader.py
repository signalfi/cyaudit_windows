"""Configuration loader module"""

import json
import logging
from pathlib import Path
from typing import Dict, Any


logger = logging.getLogger(__name__)


class ConfigLoader:
    """Load and validate configuration"""
    
    DEFAULT_CONFIG = {
        'output_directory': 'assessments',
        'logging': {
            'directory': 'logs',
            'retention_days': 30
        },
        'assessment': {
            'retention_days': 90,
            'include_system_info': True,
            'include_users': True,
            'include_groups': True,
            'include_services': True,
            'include_processes': True,
            'include_network': True,
            'include_security_policies': True,
            'include_registry': True,
            'include_installed_software': True
        },
        'splunk': {
            'enabled': False,
            'forwarder_path': 'C:\\Program Files\\SplunkUniversalForwarder',
            'monitor_path': None,
            'sourcetype': 'cyaudit:windows:assessment'
        },
        'task_scheduler': {
            'task_name': 'CyAudit_Security_Assessment',
            'schedule': 'DAILY',
            'start_time': '02:00',
            'enabled': True
        }
    }
    
    @classmethod
    def load(cls, config_path: str) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        config_file = Path(config_path)
        
        if config_file.exists():
            logger.info(f"Loading configuration from {config_path}")
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                
                # Merge with defaults
                config = cls._merge_configs(cls.DEFAULT_CONFIG.copy(), user_config)
                logger.info("Configuration loaded successfully")
                return config
            except Exception as e:
                logger.warning(f"Error loading config file: {e}. Using defaults.")
                return cls.DEFAULT_CONFIG.copy()
        else:
            logger.info(f"Config file not found: {config_path}. Using defaults.")
            return cls.DEFAULT_CONFIG.copy()
    
    @classmethod
    def _merge_configs(cls, default: Dict, user: Dict) -> Dict:
        """Recursively merge user config with defaults"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = cls._merge_configs(default[key], value)
            else:
                default[key] = value
        return default
    
    @classmethod
    def save_default(cls, config_path: str):
        """Save default configuration to file"""
        config_file = Path(config_path)
        with open(config_file, 'w') as f:
            json.dump(cls.DEFAULT_CONFIG, f, indent=2)
        logger.info(f"Default configuration saved to {config_path}")
