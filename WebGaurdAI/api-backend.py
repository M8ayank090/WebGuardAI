from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Optional
import snowflake.connector
from datetime import datetime
import asyncio
import json
import logging
from crawler import ThreatDetectionSpider
from extractor import FeatureExtractor
from detection import ThreatDetectionModel

app = FastAPI(
    title="WebGuardAI API",
    description="AI-powered web threat detection system",
    version="1.0.0"
)

# Initialize components
feature_extractor = FeatureExtractor()
threat_detector = ThreatDetectionModel()

# Pydantic models for request/response validation
class UrlRequest(BaseModel):
    url: HttpUrl
    callback_url: Optional[HttpUrl] = None

class BatchUrlRequest(BaseModel):
    urls: List[HttpUrl]
    callback_url: Optional[HttpUrl] = None

class ThreatAnalysisResponse(BaseModel):
    url: str
    timestamp: datetime
    threat_score: float
    threat_level: str
    confidence: float
    details: Dict
    
class SnowflakeConfig:
    def __init__(self):
        self.conn = snowflake.connector.connect(
            user=app.state.config['SNOWFLAKE_USER'],
            password=app.state.config['SNOWFLAKE_PASSWORD'],
            account=app.state.config['SNOWFLAKE_ACCOUNT'],
            warehouse=app.state.config['SNOWFLAKE_WAREHOUSE'],
            database=app.state.config['SNOWFLAKE_DATABASE']
        )

@app.on_event("startup")
async def startup_event():
    # Load configuration
    with open('config/api_config.json') as f:
        app.state.config = json.load(f)
    
    # Initialize Snowflake connection
    app.state.snowflake = SnowflakeConfig()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

@app.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze_url(request: UrlRequest):
    """Analyze a single URL for threats"""
    try:
        # Crawl the URL
        spider = ThreatDetectionSpider()
        response = await spider.crawl_single_url(request.url)
        
        # Extract features
        features = feature_extractor.extract_features(
            response.text,
            str(request.url)
        )
        
        # Detect threats
        threat_analysis = threat_detector.predict_threat(features)
        
        # Store results
        await store_analysis_results(
            str(request.url),
            features,
            threat_analysis
        )
        
        return ThreatAnalysisResponse(
            url=str(request.url),
            timestamp=datetime.utcnow(),
            threat_score=threat_analysis['threat_score'],
            threat_level=threat_analysis['threat_level'],
            confidence=threat_analysis['confidence'],
            details=threat_analysis['component_scores']
        )
        
    except Exception as e:
        logging.error(f"Error analyzing URL {request.url}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/batch")
async def analyze_urls_batch(request: BatchUrlRequest, background_tasks: BackgroundTasks):
    """Analyze multiple URLs asynchronously"""
    # Generate job ID
    job_id = generate_job_id()
    
    # Start background processing
    background_tasks.add_task(
        process_url_batch,
        request.urls,
        job_id,
        request.callback_url
    )
    
    return {"job_id": job_id, "status": "processing"}

async def process_url_batch(urls: List[HttpUrl], job_id: str, callback_url: Optional[HttpUrl]):
    """Process batch of URLs and send results to callback URL if provided"""
    results = []
    
    for url in urls:
        try:
            result = await analyze_url(UrlRequest(url=url))
            results.append(result)
        except Exception as e:
            logging.error(f"Error processing {url}: {str(e)}")
            results.append({
                "url": str(url),
                "error": str(e)
            })
    
    # Store batch results
    store_batch_results(job_id, results)
    
    # Send callback if URL provided
    if callback_url:
        await send_callback(callback_url, job_id, results)

@app.get("/results/{job_id}")
async def get_batch_results(job_id: str):
    """Retrieve results for a batch job"""
    results = await load_batch_results(job_id)
    if not results:
        raise HTTPException(status_code=404, detail="Job not found")
    return results

async def store_analysis_results(url: str, features: Dict, analysis: Dict):
    """Store analysis results in Snowflake"""
    cur = app.state.snowflake.conn.cursor()
    try:
        cur.execute("""
            INSERT INTO threat_analysis_results
            (url, features, analysis, timestamp)
            VALUES (%s, %s, %s, %s)
        """, (
            url,
            json.dumps(features),
            json.dumps(analysis),
            datetime.utcnow()
        ))
    finally:
        cur.close()

def generate_job_id() -> str:
    """Generate unique job ID"""
    return datetime.utcnow().strftime('%Y%m%d%H%M%S-') + str(hash(datetime.utcnow()))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
