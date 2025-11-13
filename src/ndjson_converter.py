"""NDJSON converter module - converts assessment data to Splunk-optimized NDJSON format"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


logger = logging.getLogger(__name__)


class NDJsonConverter:
    """Convert assessment data to NDJSON format for Splunk"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = Path(config.get('output_directory', 'assessments'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def convert(self, assessment_data: List[Dict[str, Any]]) -> Path:
        """Convert assessment data to NDJSON format"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.output_dir / f'cyaudit_assessment_{timestamp}.ndjson'
        
        logger.info(f"Converting {len(assessment_data)} items to NDJSON...")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for item in assessment_data:
                    # Add metadata for Splunk
                    enhanced_item = self._enhance_for_splunk(item)
                    
                    # Write as single line JSON
                    json_line = json.dumps(enhanced_item, ensure_ascii=False)
                    f.write(json_line + '\n')
            
            logger.info(f"NDJSON file created: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error converting to NDJSON: {e}")
            raise
    
    def _enhance_for_splunk(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Add Splunk-specific metadata to event"""
        enhanced = item.copy()
        
        # Add source information
        enhanced['source'] = 'cyaudit_opus'
        enhanced['sourcetype'] = self.config.get('splunk', {}).get('sourcetype', 'cyaudit:windows:assessment')
        
        # Add index time if not present
        if 'timestamp' not in enhanced:
            enhanced['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add version information
        enhanced['cyaudit_version'] = '3.4'
        
        return enhanced
