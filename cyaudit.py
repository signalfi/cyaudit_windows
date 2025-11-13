#!/usr/bin/env python3
"""
CyAudit Opus v3.4 - Windows Security Assessment Tool
Main entry point for the application
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

from src.security_assessment import SecurityAssessment
from src.ndjson_converter import NDJsonConverter
from src.splunk_forwarder import SplunkForwarder
from src.task_scheduler import TaskScheduler
from src.retention_manager import RetentionManager
from src.config_loader import ConfigLoader


VERSION = "3.4"


def setup_logging(log_dir: Path, verbose: bool = False):
    """Setup logging configuration"""
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_level = logging.DEBUG if verbose else logging.INFO
    log_file = log_dir / f"cyaudit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)


def run_assessment(config: dict, logger: logging.Logger):
    """Run a complete security assessment"""
    try:
        logger.info(f"CyAudit Opus v{VERSION} - Starting security assessment")
        
        # Initialize components
        assessment = SecurityAssessment(config)
        converter = NDJsonConverter(config)
        forwarder = SplunkForwarder(config)
        retention = RetentionManager(config)
        
        # Run security assessment
        logger.info("Running security assessment...")
        assessment_data = assessment.run()
        logger.info(f"Assessment completed. Collected {len(assessment_data)} items")
        
        # Convert to NDJSON format
        logger.info("Converting data to NDJSON format...")
        ndjson_file = converter.convert(assessment_data)
        logger.info(f"NDJSON file created: {ndjson_file}")
        
        # Forward to Splunk if configured
        if config.get('splunk', {}).get('enabled', False):
            logger.info("Forwarding data to Splunk...")
            forwarder.forward(ndjson_file)
            logger.info("Data forwarded successfully")
        
        # Clean up old assessments
        logger.info("Running retention management...")
        deleted_count = retention.cleanup()
        logger.info(f"Cleaned up {deleted_count} old files")
        
        logger.info("Assessment completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Assessment failed: {e}", exc_info=True)
        return 1


def setup_task_scheduler(config: dict, logger: logging.Logger):
    """Setup Windows Task Scheduler for automated assessments"""
    try:
        logger.info("Setting up Windows Task Scheduler...")
        scheduler = TaskScheduler(config)
        scheduler.create_task()
        logger.info("Task Scheduler setup completed")
        return 0
    except Exception as e:
        logger.error(f"Task Scheduler setup failed: {e}", exc_info=True)
        return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f'CyAudit Opus v{VERSION} - Windows Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--config',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    parser.add_argument(
        '--setup-scheduler',
        action='store_true',
        help='Setup Windows Task Scheduler for automated assessments'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'CyAudit Opus v{VERSION}'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = ConfigLoader.load(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        return 1
    
    # Setup logging
    log_dir = Path(config.get('logging', {}).get('directory', 'logs'))
    logger = setup_logging(log_dir, args.verbose)
    
    # Execute requested action
    if args.setup_scheduler:
        return setup_task_scheduler(config, logger)
    else:
        return run_assessment(config, logger)


if __name__ == '__main__':
    sys.exit(main())
