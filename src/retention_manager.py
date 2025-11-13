"""Retention manager module - manages cleanup of old assessments and logs"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List


logger = logging.getLogger(__name__)


class RetentionManager:
    """Manage retention and cleanup of assessment data and logs"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.assessment_retention_days = config.get('assessment', {}).get('retention_days', 90)
        self.log_retention_days = config.get('logging', {}).get('retention_days', 30)
        self.output_dir = Path(config.get('output_directory', 'assessments'))
        self.log_dir = Path(config.get('logging', {}).get('directory', 'logs'))
    
    def cleanup(self) -> int:
        """Clean up old assessment files and logs"""
        total_deleted = 0
        
        # Clean up old assessments
        logger.info(f"Cleaning up assessments older than {self.assessment_retention_days} days...")
        deleted_assessments = self._cleanup_directory(
            self.output_dir,
            self.assessment_retention_days,
            '*.ndjson'
        )
        total_deleted += deleted_assessments
        logger.info(f"Deleted {deleted_assessments} old assessment file(s)")
        
        # Clean up old logs
        logger.info(f"Cleaning up logs older than {self.log_retention_days} days...")
        deleted_logs = self._cleanup_directory(
            self.log_dir,
            self.log_retention_days,
            '*.log'
        )
        total_deleted += deleted_logs
        logger.info(f"Deleted {deleted_logs} old log file(s)")
        
        return total_deleted
    
    def _cleanup_directory(self, directory: Path, retention_days: int, pattern: str) -> int:
        """Clean up files in a directory older than retention days"""
        if not directory.exists():
            logger.debug(f"Directory does not exist: {directory}")
            return 0
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_count = 0
        
        try:
            for file_path in directory.glob(pattern):
                if not file_path.is_file():
                    continue
                
                # Get file modification time
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                
                if file_mtime < cutoff_date:
                    try:
                        file_path.unlink()
                        deleted_count += 1
                        logger.debug(f"Deleted old file: {file_path}")
                    except Exception as e:
                        logger.warning(f"Could not delete {file_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error cleaning up directory {directory}: {e}")
        
        return deleted_count
    
    def get_retention_status(self) -> Dict[str, Any]:
        """Get status of retention management"""
        status = {
            'assessment_retention_days': self.assessment_retention_days,
            'log_retention_days': self.log_retention_days,
            'directories': {}
        }
        
        # Check assessment directory
        if self.output_dir.exists():
            assessment_files = list(self.output_dir.glob('*.ndjson'))
            status['directories']['assessments'] = {
                'path': str(self.output_dir),
                'file_count': len(assessment_files),
                'files': [self._get_file_info(f) for f in assessment_files]
            }
        
        # Check log directory
        if self.log_dir.exists():
            log_files = list(self.log_dir.glob('*.log'))
            status['directories']['logs'] = {
                'path': str(self.log_dir),
                'file_count': len(log_files),
                'files': [self._get_file_info(f) for f in log_files]
            }
        
        return status
    
    def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get information about a file"""
        try:
            stat = file_path.stat()
            return {
                'name': file_path.name,
                'size_bytes': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'age_days': (datetime.now() - datetime.fromtimestamp(stat.st_mtime)).days
            }
        except Exception as e:
            logger.warning(f"Could not get file info for {file_path}: {e}")
            return {'name': file_path.name, 'error': str(e)}
