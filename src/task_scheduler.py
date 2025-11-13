"""Windows Task Scheduler integration module"""

import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any


logger = logging.getLogger(__name__)


class TaskScheduler:
    """Integrate with Windows Task Scheduler for automated assessments"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scheduler_config = config.get('task_scheduler', {})
        self.task_name = self.scheduler_config.get('task_name', 'CyAudit_Security_Assessment')
    
    def create_task(self):
        """Create a scheduled task for automated assessments"""
        if not self.scheduler_config.get('enabled', True):
            logger.info("Task Scheduler integration is disabled")
            return
        
        try:
            # Get Python executable and script path
            python_exe = sys.executable
            script_path = Path(__file__).parent.parent / 'cyaudit.py'
            config_path = Path('config.json').absolute()
            
            # Task parameters
            schedule = self.scheduler_config.get('schedule', 'DAILY')
            start_time = self.scheduler_config.get('start_time', '02:00')
            
            logger.info(f"Creating scheduled task: {self.task_name}")
            
            # Delete existing task if it exists
            self._delete_task()
            
            # Create the task using schtasks
            cmd = [
                'schtasks',
                '/Create',
                '/TN', self.task_name,
                '/TR', f'"{python_exe}" "{script_path}" --config "{config_path}"',
                '/SC', schedule,
                '/ST', start_time,
                '/RU', 'SYSTEM',
                '/RL', 'HIGHEST',
                '/F'  # Force create/overwrite
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"Scheduled task created successfully: {self.task_name}")
                logger.info(f"Schedule: {schedule} at {start_time}")
            else:
                logger.error(f"Failed to create scheduled task: {result.stderr}")
                raise Exception(f"Task creation failed: {result.stderr}")
            
        except Exception as e:
            logger.error(f"Error creating scheduled task: {e}")
            raise
    
    def _delete_task(self):
        """Delete existing task if it exists"""
        try:
            cmd = [
                'schtasks',
                '/Delete',
                '/TN', self.task_name,
                '/F'
            ]
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            # Don't log error if task doesn't exist
            
        except Exception:
            pass  # Task might not exist
    
    def delete_task(self):
        """Delete the scheduled task"""
        try:
            logger.info(f"Deleting scheduled task: {self.task_name}")
            
            cmd = [
                'schtasks',
                '/Delete',
                '/TN', self.task_name,
                '/F'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"Scheduled task deleted successfully: {self.task_name}")
            else:
                logger.warning(f"Could not delete task: {result.stderr}")
            
        except Exception as e:
            logger.error(f"Error deleting scheduled task: {e}")
    
    def get_task_info(self) -> Dict[str, Any]:
        """Get information about the scheduled task"""
        try:
            cmd = [
                'schtasks',
                '/Query',
                '/TN', self.task_name,
                '/FO', 'LIST',
                '/V'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return {'status': 'exists', 'details': result.stdout}
            else:
                return {'status': 'not_found'}
            
        except Exception as e:
            logger.error(f"Error querying scheduled task: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def run_task(self):
        """Run the scheduled task immediately"""
        try:
            logger.info(f"Running scheduled task: {self.task_name}")
            
            cmd = [
                'schtasks',
                '/Run',
                '/TN', self.task_name
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info("Task started successfully")
            else:
                logger.error(f"Failed to run task: {result.stderr}")
            
        except Exception as e:
            logger.error(f"Error running scheduled task: {e}")
