from fastapi import FastAPI, HTTPException, Query 
from fastapi.middleware.cors import CORSMiddleware 
from pydantic import BaseModel, Field, validator 
from typing import Optional, List, Dict, Any 
import re 
import os 
import logging 
import time 
import requests 
from datetime import datetime 
  
 # ====================== NEW: PHISHBERT AI IMPORTS ====================== 
 from transformers import pipeline 
  
 print("Loading AI Model...") 
 classifier = pipeline( 
     "text-classification", 
     model="ealvaradob/bert-finetuned-phishing", 
     truncation=True 
 ) 
 print("AI Model Loaded") 
  
 # ====================== NEW: PHISHBERT HELPER FUNCTION ====================== 
 def ai_phishing_check(text): 
     try: 
         result = classifier(text[:512])[0] 
         label = result["label"].upper() 
         confidence = float(result["score"]) 
  
         if "PHISH" in label: 
             return { 
                 "is_phishing": True, 
                 "confidence": confidence 
             } 
  
         return { 
             "is_phishing": False, 
             "confidence": confidence 
         } 
     except Exception as e: 
         print("AI ERROR:", str(e)) 
         return { 
             "is_phishing": False, 
             "confidence": 0 
         } 
  
 # ====================== LOGGING SETUP ====================== 
  
 logging.basicConfig( 
     level=logging.INFO, 
     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s" 
 ) 
 logger = logging.getLogger(__name__) 
  
 # ====================== FASTAPI APP ====================== 
  
 app = FastAPI( 
     title="BharatCyber EduShield with AI", 
     description="AI-Powered Cybersecurity Education Platform for Rural India", 
     version="2.0.0" 
 ) 
  
 # ====================== CORS CONFIGURATION ====================== 
  
 ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",") 
  
 app.add_middleware( 
     CORSMiddleware, 
     allow_origins=ALLOWED_ORIGINS, 
     allow_credentials=True, 
     allow_methods=["*"], 
     allow_headers=["*"], 
 ) 
  
 # ====================== ENVIRONMENT CONFIGURATION ====================== 
  
 VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") 
 MAX_INPUT_LENGTH = 5000 
 MAX_URL_LENGTH = 2048 
  
 # Log configuration at startup 
 if not VT_API_KEY: 
     logger.warning( 
         "⚠️ VIRUSTOTAL_API_KEY not set. URL analysis will use heuristics only." 
     ) 
 else: 
     logger.info("✅ VirusTotal API key loaded successfully") 
  
 # ====================== TEMPORARY STORAGE ====================== 
  
 scans_history: List[Dict[str, Any]] = [] 
 dpdp_logs: List[Dict[str, Any]] = [] 
  
 # ====================== PYDANTIC MODELS ====================== 
  
 class ScanRequest(BaseModel): 
     """Request model for phishing detection""" 
      
     text: str = Field( 
         ..., 
         min_length=3, 
         max_length=MAX_INPUT_LENGTH, 
         description="URL or text content to scan for phishing" 
     ) 
     user_id: Optional[str] = Field( 
         default="demo_teacher", 
         max_length=100, 
         description="Identifier for the teacher/admin performing the scan" 
     ) 
      
     @validator("text") 
     def text_must_not_be_empty(cls, v: str) -> str: 
         if not v.strip(): 
             raise ValueError("Text cannot be empty or only whitespace") 
         return v.strip() 
      
     @validator("user_id") 
     def user_id_format(cls, v: Optional[str]) -> Optional[str]: 
         if v and not re.match(r"^[a-zA-Z0-9_\-\.@]{1,100}$", v): 
             raise ValueError("user_id contains invalid characters") 
         return v 
  
  
 class ScanResponse(BaseModel): 
     """Response model for phishing detection results""" 
      
     is_phishing: bool 
     input_type: str 
     score: int 
     risk_level: str 
     confidence: float 
     message: str 
     confidence_percent: str 
     recommendation: str 
     timestamp: str 
     teacher_alert: Optional[str] = None 
     model_used: str = Field( 
         default="heuristic", 
         description="Which model was used: 'heuristic', 'phishbert', 'virustotal', 'ensemble'" 
     ) 
     note: str = Field( 
         default="EduShield AI Detection Engine", 
         description="System note" 
     ) 
  
  
 class HistoryResponse(BaseModel): 
     """Response model for scan history""" 
      
     total_scans: int 
     scans: List[Dict[str, Any]] 
  
  
 class DPDPLogsResponse(BaseModel): 
     """Response model for DPDP compliance logs""" 
      
     total_logs: int 
     logs: List[Dict[str, Any]] 
  
  
 class AdminStatsResponse(BaseModel): 
     """Response model for admin statistics""" 
      
     schools_protected: int 
     real_time_threats: int 
     dpdp_compliance: str 
     students_protected_today: int 
     high_risk: int 
     medium_risk: int 
     low_risk: int 
     ai_scans: int = 0 
     heuristic_scans: int = 0 
  
  
 class HealthResponse(BaseModel): 
     """Response model for health check""" 
      
     status: str 
     virustotal_api: str 
     ai_model: str 
     timestamp: str 
  
 # ====================== VIRUSTOTAL INTEGRATION ====================== 
  
 def check_url_virustotal(url: str) -> Optional[Dict[str, Any]]: 
     """Submit URL to VirusTotal for threat analysis with retry logic.""" 
      
     if not VT_API_KEY: 
         logger.debug("VirusTotal API key not configured") 
         return None 
      
     if not url.startswith(("http://", "https://")): 
         logger.warning(f"Invalid URL format: {url}") 
         return None 
      
     if len(url) > MAX_URL_LENGTH: 
         logger.warning(f"URL exceeds max length: {len(url)}") 
         return None 
      
     try: 
         headers = {"x-apikey": VT_API_KEY} 
          
         # Submit URL 
         logger.info(f"Submitting URL to VirusTotal: {url[:50]}...") 
         submit_response = requests.post( 
             "https://www.virustotal.com/api/v3/urls", 
             headers=headers, 
             data={"url": url}, 
             timeout=10 
         ) 
          
         if submit_response.status_code not in [200, 201]: 
             logger.warning(f"VirusTotal submit failed: {submit_response.status_code}") 
             return None 
          
         try: 
             response_data = submit_response.json() 
             if "data" not in response_data or "id" not in response_data.get("data", {}): 
                 logger.error("VirusTotal response missing required fields") 
                 return None 
              
             analysis_id = response_data["data"]["id"] 
         except (ValueError, KeyError) as e: 
             logger.error(f"Failed to parse VirusTotal response: {e}") 
             return None 
          
         # Fetch analysis results with retry 
         logger.info(f"Fetching analysis for ID: {analysis_id}") 
          
         for attempt in range(1, 4): 
             try: 
                 report_response = requests.get( 
                     f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", 
                     headers=headers, 
                     timeout=10 
                 ) 
                  
                 if report_response.status_code != 200: 
                     if attempt < 3: 
                         time.sleep(1) 
                     continue 
                  
                 try: 
                     report_data = report_response.json() 
                     if "data" not in report_data or "attributes" not in report_data.get("data", {}): 
                         if attempt < 3: 
                             time.sleep(1) 
                         continue 
                      
                     logger.info(f"VirusTotal analysis complete") 
                     return report_data 
                      
                 except (ValueError, KeyError) as e: 
                     logger.error(f"Parse error (attempt {attempt}/3): {e}") 
                     if attempt < 3: 
                         time.sleep(1) 
                     continue 
                      
             except requests.exceptions.Timeout: 
                 logger.warning(f"Timeout (attempt {attempt}/3)") 
                 if attempt < 3: 
                     time.sleep(1) 
                 continue 
          
         logger.warning("VirusTotal analysis failed after 3 attempts") 
         return None 
          
     except requests.exceptions.RequestException as e: 
         logger.error(f"VirusTotal request error: {e}") 
         return None 
     except Exception as e: 
         logger.error(f"Unexpected error in VirusTotal check: {e}", exc_info=True) 
         return None 
  
 # ====================== URL VALIDATION ====================== 
  
 def is_valid_url(url: str) -> bool: 
     """Validate URL format with regex.""" 
     url_pattern = re.compile( 
         r"^https?://" 
         r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*" 
         r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)" 
         r"(?:\:\d+)?" 
         r"(?:/[^\s]*)?" 
         r"$", 
         re.IGNORECASE 
     ) 
     return bool(url_pattern.match(url)) 
  
 # ====================== PHISHING DETECTION ENGINE ====================== 
  
 @app.post("/detect", response_model=ScanResponse) 
 async def detect_phishing(request: ScanRequest) -> ScanResponse: 
     """ 
     Detect phishing threats using the new workflow: 
     PhishBERT AI -> Keyword Detection -> VirusTotal -> Final Risk Score 
     """ 
     try: 
         if not request.text or len(request.text.strip()) < 3: 
             raise HTTPException( 
                 status_code=400, 
                 detail="Input text is too short (minimum 3 characters)" 
             ) 
          
         text_lower = request.text.lower().strip() 
         score = 0 
         risk_level = "LOW" 
         teacher_alert: Optional[str] = None 
         model_used = "phishbert" 
         virustotal_used = False 
          
         # ====================== FIRST: RUN PHISHBERT AI (as per your guide) ====================== 
         ai_result = ai_phishing_check(request.text) 
          
         # ====================== URL DETECTION ====================== 
          
         url_match = re.search( 
             r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=])+', 
             request.text 
         ) 
          
         input_type = "URL" if url_match else "TEXT" 
          
         # ====================== URL ANALYSIS ====================== 
          
         if url_match: 
             url = url_match.group() 
              
             if not is_valid_url(url): 
                 logger.warning(f"Invalid URL format: {url[:50]}") 
                 score += 30 
             else: 
                 # Try VirusTotal first 
                 vt_result = check_url_virustotal(url) 
                  
                 if vt_result: 
                     virustotal_used = True 
                     model_used = "ensemble" 
                     try: 
                         stats = ( 
                             vt_result 
                             .get("data", {}) 
                             .get("attributes", {}) 
                             .get("stats", {}) 
                         ) 
                          
                         malicious = stats.get("malicious", 0) 
                         suspicious = stats.get("suspicious", 0) 
                          
                         if malicious > 0: 
                             score += 95 
                         elif suspicious > 0: 
                             score += 65 
                         else: 
                             score += 10 
                              
                     except (KeyError, TypeError) as e: 
                         logger.error(f"VT parse error: {e}") 
                         score += 20 
                  
                 # Fallback to heuristics if VT unavailable 
                 if not virustotal_used: 
                     score += 20 
                     if url.startswith("http://"): 
                         score += 20 
                      
                     suspicious_patterns = [ 
                         "login", "verify", "bank", "reward", "claim", 
                         "otp", "upi", "secure", "gift", "winner" 
                     ] 
                      
                     for pattern in suspicious_patterns: 
                         if pattern in text_lower: 
                             score += 15 
          
         # ====================== TEXT ANALYSIS (Heuristics) ====================== 
          
         else: 
             # Heuristic analysis 
             phishing_keywords = [ 
                 "click here", "urgent", "exam result", "admit card", 
                 "scholarship", "verify your account", "bank details", 
                 "password", "login now", "reward", "free", "limited time", 
                 "government scheme", "otp", "upi", "verify", "winner", 
                 "congratulations", "claim now", "confirm identity", 
                 "update payment", "act now", "respond immediately" 
             ] 
              
             for keyword in phishing_keywords: 
                 if keyword in text_lower: 
                     score += 15 
              
             if re.search(r'https?://\S+', request.text): 
                 score += 30 
          
         # ====================== APPLY AI RESULT (as per your guide) ====================== 
         if ai_result["is_phishing"]: 
             score += int(ai_result["confidence"] * 50) 
          
         # ====================== FINAL SCORE CALCULATION ====================== 
          
         score = min(score, 100) 
          
         if score >= 70: 
             risk_level = "HIGH" 
         elif score >= 40: 
             risk_level = "MEDIUM" 
         else: 
             risk_level = "LOW" 
          
         is_phishing = score >= 40 
          
         if risk_level == "HIGH": 
             teacher_alert = f"🚨 High Risk Threat Detected for {request.user_id}" 
          
         # ====================== BUILD RESPONSE ====================== 
          
         timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
          
         result = ScanResponse( 
             is_phishing=is_phishing, 
             input_type=input_type, 
             score=score, 
             risk_level=risk_level, 
             confidence=float(score) / 100, 
             message=( 
                 "🚨 High Risk Threat Detected" 
                 if risk_level == "HIGH" 
                 else "⚠️ Suspicious Content Found" 
                 if risk_level == "MEDIUM" 
                 else "✅ Looks Safe" 
             ), 
             confidence_percent=f"{score}%", 
             recommendation=( 
                 "Block Immediately" 
                 if risk_level == "HIGH" 
                 else "Review Carefully" 
                 if risk_level == "MEDIUM" 
                 else "Safe To Use" 
             ), 
             timestamp=timestamp_str, 
             teacher_alert=teacher_alert, 
             model_used=model_used 
         ) 
          
         # ====================== SAVE TO HISTORY ====================== 
          
         text_for_history = request.text[:150] 
          
         scans_history.append({ 
             "id": len(scans_history) + 1, 
             "user_id": request.user_id, 
             "text": text_for_history, 
             "input_type": input_type, 
             "is_phishing": result.is_phishing, 
             "score": result.score, 
             "risk_level": result.risk_level, 
             "confidence": result.confidence, 
             "timestamp": result.timestamp, 
             "model_used": model_used, 
             "virustotal_used": virustotal_used, 
             "ai_confidence": ai_result["confidence"] 
         }) 
          
         # ====================== SAVE DPDP COMPLIANCE LOGS ====================== 
          
         dpdp_logs.append({ 
             "timestamp": result.timestamp, 
             "user_id": request.user_id, 
             "action": "phishing_scan", 
             "input_type": input_type, 
             "is_phishing": result.is_phishing, 
             "score": result.score, 
             "risk_level": result.risk_level, 
             "model_used": model_used 
         }) 
          
         logger.info( 
             f"Scan complete: type={input_type}, risk={risk_level}, " 
             f"score={score}, model={model_used}, " 
             f"ai_confidence={ai_result['confidence']:.2f}" 
         ) 
          
         return result 
          
     except HTTPException: 
         raise 
     except Exception as e: 
         logger.error(f"Detect error: {e}", exc_info=True) 
         raise HTTPException(status_code=500, detail="Detection failed") 
  
 # ====================== SCAN HISTORY ENDPOINT ====================== 
  
 @app.get("/scans/history", response_model=HistoryResponse) 
 async def get_scan_history( 
     user_id: Optional[str] = Query(None, max_length=100) 
 ) -> HistoryResponse: 
     """Retrieve phishing scan history.""" 
      
     try: 
         if user_id: 
             if not re.match(r"^[a-zA-Z0-9_\-\.@]{1,100}$", user_id): 
                 raise HTTPException(status_code=400, detail="Invalid user_id") 
              
             history = [s for s in scans_history if s["user_id"] == user_id] 
         else: 
             history = scans_history[-30:] 
          
         return HistoryResponse( 
             total_scans=len(history), 
             scans=history[::-1] 
         ) 
          
     except Exception as e: 
         logger.error(f"History error: {e}") 
         raise HTTPException(status_code=500, detail="Failed to retrieve history") 
  
 # ====================== DPDP LOGS ENDPOINT ====================== 
  
 @app.get("/dpdp/logs", response_model=DPDPLogsResponse) 
 async def get_dpdp_logs() -> DPDPLogsResponse: 
     """Retrieve DPDP compliance logs.""" 
      
     try: 
         return DPDPLogsResponse( 
             total_logs=len(dpdp_logs), 
             logs=dpdp_logs[-20:] 
         ) 
     except Exception as e: 
         logger.error(f"DPDP logs error: {e}") 
         raise HTTPException(status_code=500, detail="Failed to retrieve logs") 
  
 # ====================== ADMIN STATISTICS ENDPOINT ====================== 
  
 @app.get("/admin/stats", response_model=AdminStatsResponse) 
 async def admin_stats() -> AdminStatsResponse: 
     """Retrieve admin dashboard statistics.""" 
      
     try: 
         total_scans = len(scans_history) 
         high_risk = len([x for x in scans_history if x["risk_level"] == "HIGH"]) 
         medium_risk = len([x for x in scans_history if x["risk_level"] == "MEDIUM"]) 
         low_risk = len([x for x in scans_history if x["risk_level"] == "LOW"]) 
          
         ai_scans = len([x for x in scans_history if x.get("ai_confidence", 0) > 0]) 
         heuristic_scans = total_scans - ai_scans 
          
         return AdminStatsResponse( 
             schools_protected=4, 
             real_time_threats=high_risk + medium_risk, 
             dpdp_compliance="93%", 
             students_protected_today=total_scans, 
             high_risk=high_risk, 
             medium_risk=medium_risk, 
             low_risk=low_risk, 
             ai_scans=ai_scans, 
             heuristic_scans=heuristic_scans 
         ) 
          
     except Exception as e: 
         logger.error(f"Stats error: {e}") 
         raise HTTPException(status_code=500, detail="Failed to retrieve stats") 
  
 # ====================== HEALTH CHECK ENDPOINT ====================== 
  
 @app.get("/health", response_model=HealthResponse) 
 async def health_check() -> HealthResponse: 
     """Health check endpoint.""" 
      
     try: 
         vt_status = "configured" if VT_API_KEY else "not_configured" 
         ai_status = "ready" 
          
         return HealthResponse( 
             status="healthy", 
             virustotal_api=vt_status, 
             ai_model=ai_status, 
             timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
         ) 
     except Exception as e: 
         logger.error(f"Health check error: {e}") 
         raise HTTPException(status_code=503, detail="Unhealthy") 
  
 # ====================== ROOT ENDPOINT ====================== 
  
 @app.get("/") 
 async def root() -> Dict[str, Any]: 
     """Root endpoint with API information.""" 
      
     return { 
         "message": "✅ BharatCyber EduShield with PhishBERT AI Backend Running", 
         "status": "Ready", 
         "version": "2.0.0", 
         "ai_model": "ealvaradob/bert-finetuned-phishing", 
         "endpoints": { 
             "detect": "POST /detect - Scan for phishing (PhishBERT + heuristic)", 
             "history": "GET /scans/history - Scan history", 
             "dpdp_logs": "GET /dpdp/logs - Compliance logs", 
             "admin_stats": "GET /admin/stats - Statistics", 
             "health": "GET /health - Health check", 
             "docs": "GET /docs - OpenAPI docs" 
         } 
     } 
  
 # ====================== STARTUP/SHUTDOWN ====================== 
  
 @app.on_event("shutdown") 
 async def shutdown_event(): 
     """Shutdown logging.""" 
      
     logger.info("🛑 Backend Shutting Down") 
     logger.info(f"Total scans: {len(scans_history)}") 
     logger.info(f"Total logs: {len(dpdp_logs)}")
