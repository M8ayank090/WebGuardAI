import snowflake.connector
from snowflake.connector.pandas_tools import write_pandas
import pandas as pd
from typing import Dict, List, Optional, Union
import json
from datetime import datetime
import logging
from contextlib import contextmanager

class SnowflakeConnector:
    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.setup_logging()
        self.initialize_connection()
        self.create_tables()
        
    def setup_logging(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
    def initialize_connection(self):
        """Initialize Snowflake connection with retry logic"""
        try:
            self.conn = snowflake.connector.connect(
                user=self.config['SNOWFLAKE_USER'],
                password=self.config['SNOWFLAKE_PASSWORD'],
                account=self.config['SNOWFLAKE_ACCOUNT'],
                warehouse=self.config['SNOWFLAKE_WAREHOUSE'],
                database=self.config['SNOWFLAKE_DATABASE'],
                schema=self.config['SNOWFLAKE_SCHEMA']
            )
            self.logger.info("Successfully connected to Snowflake")
        except Exception as e:
            self.logger.error(f"Failed to connect to Snowflake: {str(e)}")
            raise
            
    @contextmanager
    def get_cursor(self):
        """Context manager for handling Snowflake cursors"""
        cursor = self.conn.cursor()
        try:
            yield cursor
        finally:
            cursor.close()
            
    def create_tables(self):
        """Create necessary tables if they don't exist"""
        with self.get_cursor() as cursor:
            # Raw crawl data table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS raw_crawl_data (
                    id NUMBER AUTOINCREMENT,
                    url VARCHAR,
                    timestamp TIMESTAMP_NTZ,
                    html_content VARCHAR,
                    headers VARIANT,
                    status INTEGER,
                    PRIMARY KEY (id)
                )
            """)
            
            # Feature extraction results
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS extracted_features (
                    id NUMBER AUTOINCREMENT,
                    crawl_id NUMBER,
                    text_features VARIANT,
                    image_features VARIANT,
                    url_features VARIANT,
                    timestamp TIMESTAMP_NTZ,
                    PRIMARY KEY (id),
                    FOREIGN KEY (crawl_id) REFERENCES raw_crawl_data(id)
                )
            """)
            
            # Threat analysis results
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_analysis (
                    id NUMBER AUTOINCREMENT,
                    feature_id NUMBER,
                    threat_score FLOAT,
                    threat_level VARCHAR,
                    confidence FLOAT,
                    component_scores VARIANT,
                    timestamp TIMESTAMP_NTZ,
                    PRIMARY KEY (id),
                    FOREIGN KEY (feature_id) REFERENCES extracted_features(id)
                )
            """)
            
    def store_crawl_data(self, data: Dict) -> int:
        """Store raw crawl data and return the inserted ID"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO raw_crawl_data (url, timestamp, html_content, headers, status)
                VALUES (%s, %s, %s, parse_json(%s), %s)
                RETURNING id
            """, (
                data['url'],
                datetime.utcnow(),
                data['html_content'],
                json.dumps(data['headers']),
                data['status']
            ))
            return cursor.fetchone()[0]
            
    def store_features(self, crawl_id: int, features: Dict) -> int:
        """Store extracted features and return the inserted ID"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO extracted_features 
                (crawl_id, text_features, image_features, url_features, timestamp)
                VALUES (%s, parse_json(%s), parse_json(%s), parse_json(%s), %s)
                RETURNING id
            """, (
                crawl_id,
                json.dumps(features['text_features']),
                json.dumps(features['image_features']),
                json.dumps(features['url_features']),
                datetime.utcnow()
            ))
            return cursor.fetchone()[0]
            
    def store_analysis(self, feature_id: int, analysis: Dict):
        """Store threat analysis results"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO threat_analysis 
                (feature_id, threat_score, threat_level, confidence, 
                 component_scores, timestamp)
                VALUES (%s, %s, %s, %s, parse_json(%s), %s)
            """, (
                feature_id,
                analysis['threat_score'],
                analysis['threat_level'],
                analysis['confidence'],
                json.dumps(analysis['component_scores']),
                datetime.utcnow()
            ))
            
    def get_analysis_results(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        threat_level: Optional[str] = None,
        limit: int = 1000
    ) -> pd.DataFrame:
        """Retrieve analysis results with optional filters"""
        query = """
            SELECT 
                r.url,
                t.threat_score,
                t.threat_level,
                t.confidence,
                t.component_scores,
                t.timestamp
            FROM threat_analysis t
            JOIN extracted_features f ON t.feature_id = f.id
            JOIN raw_crawl_data r ON f.crawl_id = r.id
            WHERE 1=1
        """
        params = []
        
        if start_date:
            query += " AND t.timestamp >= %s"
            params.append(start_date)
        
        if end_date:
            query += " AND t.timestamp <= %s"
            params.append(end_date)
            
        if threat_level:
            query += " AND t.threat_level = %s"
            params.append(threat_level)
            
        query += f" ORDER BY t.timestamp DESC LIMIT {limit}"
        
        return pd.read_sql(query, self.conn, params=params)
        
    def close(self):
        """Close the Snowflake connection"""
        if hasattr(self, 'conn'):
            self.conn.close()
