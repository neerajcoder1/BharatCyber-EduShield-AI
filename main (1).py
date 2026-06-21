"""
BharatCyber EduShield - AI-Powered Cybersecurity Education Platform
Production-Grade Backend with Full Error Handling
"""

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

# ====================== LOGGING SETUP ======================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ====================== FASTAPI APP ======================

app = FastAPI(
    title="BharatCyber EduShield",
    description="AI-Powered Cybersecurity Education Platform for Rural India",
    version="1.0.0"
)

# ====================== CORS CONFIGURATION ======================

# In production, replace "*" with specific origins
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
# WARNING: In production, use Redis, PostgreSQL, or similar

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
        """Validate that text is not just whitespace"""
        if not v.strip():
            raise ValueError("Text cannot be empty or only whitespace")
        return v.strip()

    @validator("user_id")
    def user_id_format(cls, v: Optional[str]) -> Optional[str]:
        """Validate user_id format"""
        if v and not re.match(r"^[a-zA-Z0-9_\-\.@]{1,100}$", v):
            raise ValueError("user_id contains invalid characters")
        return v


class ScanResponse(BaseModel):
    """Response model for phishing detection results"""

    is_phishing: bool = Field(
        ...,
        description="Boolean indicator of phishing threat"
    )
    input_type: str = Field(
        ...,
        description="Type of input: 'URL' or 'TEXT'"
    )
    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Threat score from 0-100"
    )
    risk_level: str = Field(
        ...,
        description="Risk level: 'HIGH', 'MEDIUM', or 'LOW'"
    )
    confidence: float = Field(
        ...,
        ge=0,
        le=100,
        description="Confidence score as percentage"
    )
    message: str = Field(
        ...,
        description="User-friendly threat message"
    )
    confidence_percent: str = Field(
        ...,
        description="Confidence percentage string"
    )
    recommendation: str = Field(
        ...,
        description="Recommended action"
    )
    timestamp: str = Field(
        ...,
        description="ISO format timestamp of scan"
    )
    teacher_alert: Optional[str] = Field(
        default=None,
        description="Alert message for teachers on high-risk threats"
    )
    note: str = Field(
        default="EduShield AI Detection Engine",
        description="System note"
    )


class HistoryResponse(BaseModel):
    """Response model for scan history"""

    total_scans: int = Field(...)
    scans: List[Dict[str, Any]] = Field(...)


class DPDPLogsResponse(BaseModel):
    """Response model for DPDP compliance logs"""

    total_logs: int = Field(...)
    logs: List[Dict[str, Any]] = Field(...)


class AdminStatsResponse(BaseModel):
    """Response model for admin statistics"""

    schools_protected: int = Field(...)
    real_time_threats: int = Field(...)
    dpdp_compliance: str = Field(...)
    students_protected_today: int = Field(...)
    high_risk: int = Field(...)
    medium_risk: int = Field(...)
    low_risk: int = Field(...)


class HealthResponse(BaseModel):
    """Response model for health check"""

    status: str = Field(...)
    virustotal_api: str = Field(...)
    timestamp: str = Field(...)

# ====================== VIRUSTOTAL INTEGRATION ======================


def check_url_virustotal(url: str) -> Optional[Dict[str, Any]]:
    """
    Submit URL to VirusTotal for threat analysis with retry logic.

    Args:
        url: URL to scan

    Returns:
        Analysis results dict if successful, None otherwise
    """
    if not VT_API_KEY:
        logger.debug("VirusTotal API key not configured, skipping VT check")
        return None

    if not url.startswith(("http://", "https://")):
        logger.warning(f"Invalid URL format: {url}")
        return None

    if len(url) > MAX_URL_LENGTH:
        logger.warning(f"URL exceeds max length: {len(url)} > {MAX_URL_LENGTH}")
        return None

    try:
        headers = {"x-apikey": VT_API_KEY}

        # Step 1: Submit URL for analysis
        logger.info(f"Submitting URL to VirusTotal: {url[:50]}...")
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        # ✅ FIX: Accept both 200 and 201 status codes
        if submit_response.status_code not in [200, 201]:
            logger.warning(
                f"VirusTotal submit failed: {submit_response.status_code}"
            )
            return None

        # ✅ FIX: Validate response structure before accessing
        try:
            response_data = submit_response.json()
            if "data" not in response_data:
                logger.error("VirusTotal response missing 'data' field")
                return None

            if "id" not in response_data.get("data", {}):
                logger.error("VirusTotal response missing 'id' field")
                return None

            analysis_id = response_data["data"]["id"]
        except (ValueError, KeyError) as e:
            logger.error(f"Failed to parse VirusTotal submit response: {e}")
            return None

        # Step 2: Fetch analysis results with retry logic
        # ✅ FIX: Implement retry mechanism (VirusTotal analysis is async)
        logger.info(f"Fetching analysis results for ID: {analysis_id}")

        for attempt in range(1, 4):
            try:
                report_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10
                )

                if report_response.status_code != 200:
                    logger.warning(
                        f"VirusTotal fetch failed (attempt {attempt}/3): "
                        f"{report_response.status_code}"
                    )
                    if attempt < 3:
                        time.sleep(1)  # Wait before retry
                    continue

                # ✅ FIX: Validate response structure
                try:
                    report_data = report_response.json()
                    if "data" not in report_data:
                        logger.warning(
                            f"VirusTotal analysis response missing 'data' "
                            f"(attempt {attempt}/3)"
                        )
                        if attempt < 3:
                            time.sleep(1)
                        continue

                    if "attributes" not in report_data.get("data", {}):
                        logger.warning(
                            f"VirusTotal analysis incomplete "
                            f"(attempt {attempt}/3)"
                        )
                        if attempt < 3:
                            time.sleep(1)
                        continue

                    # Success - we have complete analysis
                    logger.info(
                        f"VirusTotal analysis complete for {url[:50]}..."
                    )
                    return report_data

                except (ValueError, KeyError) as e:
                    logger.error(
                        f"Failed to parse VirusTotal analysis response "
                        f"(attempt {attempt}/3): {e}"
                    )
                    if attempt < 3:
                        time.sleep(1)
                    continue

            except requests.exceptions.Timeout:
                logger.warning(
                    f"VirusTotal request timeout (attempt {attempt}/3)"
                )
                if attempt < 3:
                    time.sleep(1)
                continue

        logger.warning(
            f"VirusTotal analysis failed after 3 attempts for {url[:50]}..."
        )
        return None

    # ✅ FIX: Specific exception handling (not bare except)
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal request error: {type(e).__name__}: {e}")
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error in VirusTotal check: {type(e).__name__}: {e}",
            exc_info=True
        )
        return None


# ====================== URL VALIDATION ======================


def is_valid_url(url: str) -> bool:
    """
    Validate URL format with regex.

    Args:
        url: URL string to validate

    Returns:
        True if valid URL format, False otherwise
    """
    url_pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"  # domain
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)"  # TLD
        r"(?:\:\d+)?"  # optional port
        r"(?:/[^\s]*)?"  # optional path
        r"$",
        re.IGNORECASE
    )
    return bool(url_pattern.match(url))


# ====================== PHISHING DETECTION ENGINE ======================


@app.post("/detect", response_model=ScanResponse)
async def detect_phishing(request: ScanRequest) -> ScanResponse:
    """
    Detect phishing threats in URLs or text content.

    Uses VirusTotal for URLs if available, with fallback heuristics.
    Scans text content for phishing keywords and suspicious patterns.

    Args:
        request: ScanRequest with text content and user_id

    Returns:
        ScanResponse with threat analysis results
    """
    try:
        # Input validation
        if not request.text or len(request.text.strip()) < 3:
            raise HTTPException(
                status_code=400,
                detail="Input text is too short (minimum 3 characters)"
            )

        text_lower = request.text.lower().strip()

        # Initialize scoring
        score = 0
        risk_level = "LOW"
        teacher_alert: Optional[str] = None
        virustotal_used = False

        # ====================== URL DETECTION ======================

        # ✅ IMPROVED: Better URL regex pattern
        url_match = re.search(
            r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=])+',
            request.text
        )

        input_type = "URL" if url_match else "TEXT"

        # ====================== URL ANALYSIS BRANCH ======================

        if url_match:
            url = url_match.group()

            # Validate URL format
            if not is_valid_url(url):
                logger.warning(f"Invalid URL format detected: {url[:50]}")
                score = 30  # Suspicious URL format
            else:
                # Try VirusTotal analysis first
                vt_result = check_url_virustotal(url)

                if vt_result:
                    virustotal_used = True
                    try:
                        # ✅ FIX: Safe nested dict access
                        stats = (
                            vt_result
                            .get("data", {})
                            .get("attributes", {})
                            .get("stats", {})
                        )

                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)

                        # Assign score based on VirusTotal verdict
                        if malicious > 0:
                            score = 95
                            logger.info(f"VirusTotal: MALICIOUS ({malicious})")
                        elif suspicious > 0:
                            score = 65
                            logger.info(
                                f"VirusTotal: SUSPICIOUS ({suspicious})"
                            )
                        else:
                            score = 10
                            logger.info("VirusTotal: CLEAN")

                    except (KeyError, TypeError) as e:
                        logger.error(
                            f"Error parsing VirusTotal response: {e}. "
                            f"Falling back to heuristics."
                        )
                        # Fallback if parsing fails
                        score = 20

                # ✅ FALLBACK: Heuristic analysis if VT unavailable
                if not virustotal_used:
                    logger.info(
                        f"Using heuristic analysis for URL: {url[:50]}..."
                    )

                    score = 20  # Base score for unverified URL

                    # Penalize HTTP (unencrypted)
                    if url.startswith("http://"):
                        score += 20

                    # Check for suspicious URL patterns
                    suspicious_patterns = [
                        "login",
                        "verify",
                        "bank",
                        "reward",
                        "claim",
                        "otp",
                        "upi",
                        "secure",
                        "gift",
                        "winner",
                        "confirm",
                        "update",
                        "account",
                        "password"
                    ]

                    for pattern in suspicious_patterns:
                        if pattern in text_lower:
                            score += 15

        # ====================== TEXT ANALYSIS BRANCH ======================

        else:
            # Scan for phishing keywords
            phishing_keywords = [
                "click here",
                "urgent",
                "exam result",
                "admit card",
                "scholarship",
                "verify your account",
                "bank details",
                "password",
                "login now",
                "reward",
                "free",
                "limited time",
                "government scheme",
                "phishing",
                "suspicious",
                "otp",
                "upi",
                "verify",
                "winner",
                "congratulations",
                "claim now",
                "confirm identity",
                "update payment",
                "act now",
                "respond immediately"
            ]

            for keyword in phishing_keywords:
                if keyword in text_lower:
                    score += 15

            # Additional penalty if URL is found in text
            if re.search(r'https?://\S+', request.text):
                score += 30

        # ====================== RISK LEVEL CALCULATION ======================

        score = min(score, 100)  # Cap at 100

        if score >= 70:
            risk_level = "HIGH"
        elif score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        is_phishing = score >= 40

        # ====================== TEACHER ALERTS ======================

        if risk_level == "HIGH":
            teacher_alert = f"🚨 High Risk Threat Detected for {request.user_id}"

        # ====================== BUILD RESPONSE ======================

        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        result = ScanResponse(
            is_phishing=is_phishing,
            input_type=input_type,
            score=score,
            risk_level=risk_level,
            confidence=float(score),
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
            teacher_alert=teacher_alert
        )

        # ====================== SAVE TO HISTORY ======================

        # ✅ FIX: Truncate text in history (security)
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
            "virustotal_used": virustotal_used
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
            "virustotal_used": virustotal_used
        })

        logger.info(
            f"Scan completed: user_id={request.user_id}, "
            f"type={input_type}, risk={risk_level}, score={score}"
        )

        return result

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Validation error in detect endpoint: {e}")
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(
            f"Unexpected error in detect endpoint: {type(e).__name__}: {e}",
            exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail="Internal server error during threat detection"
        )


# ====================== SCAN HISTORY ENDPOINT ======================


@app.get("/scans/history", response_model=HistoryResponse)
async def get_scan_history(
    user_id: Optional[str] = Query(None, max_length=100)
) -> HistoryResponse:
    """
    Retrieve phishing scan history.

    Args:
        user_id: Optional filter by specific user

    Returns:
        HistoryResponse with total scans and scan records
    """
    try:
        if user_id:
            # Validate user_id
            if not re.match(r"^[a-zA-Z0-9_\-\.@]{1,100}$", user_id):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid user_id format"
                )

            history = [
                scan
                for scan in scans_history
                if scan["user_id"] == user_id
            ]
        else:
            history = scans_history[-30:]  # Last 30 scans

        return HistoryResponse(
            total_scans=len(history),
            scans=history[::-1]  # Reverse for newest first
        )

    except Exception as e:
        logger.error(f"Error retrieving scan history: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve scan history"
        )


# ====================== DPDP COMPLIANCE LOGS ENDPOINT ======================


@app.get("/dpdp/logs", response_model=DPDPLogsResponse)
async def get_dpdp_logs() -> DPDPLogsResponse:
    """
    Retrieve DPDP (Data Protection & Privacy) compliance logs.

    Returns:
        DPDPLogsResponse with total logs and recent log records
    """
    try:
        return DPDPLogsResponse(
            total_logs=len(dpdp_logs),
            logs=dpdp_logs[-20:]  # Last 20 logs
        )
    except Exception as e:
        logger.error(f"Error retrieving DPDP logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve compliance logs"
        )


# ====================== ADMIN STATISTICS ENDPOINT ======================


@app.get("/admin/stats", response_model=AdminStatsResponse)
async def admin_stats() -> AdminStatsResponse:
    """
    Retrieve admin dashboard statistics.

    Returns:
        AdminStatsResponse with threat and coverage metrics
    """
    try:
        total_scans = len(scans_history)

        high_risk = len([
            x for x in scans_history
            if x["risk_level"] == "HIGH"
        ])

        medium_risk = len([
            x for x in scans_history
            if x["risk_level"] == "MEDIUM"
        ])

        low_risk = len([
            x for x in scans_history
            if x["risk_level"] == "LOW"
        ])

        return AdminStatsResponse(
            schools_protected=4,
            real_time_threats=high_risk + medium_risk,
            dpdp_compliance="93%",
            students_protected_today=total_scans,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk
        )

    except Exception as e:
        logger.error(f"Error retrieving admin stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve statistics"
        )


# ====================== HEALTH CHECK ENDPOINT ======================


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Health check endpoint for load balancers and monitoring.

    Returns:
        HealthResponse with service status
    """
    try:
        vt_status = "configured" if VT_API_KEY else "not_configured"

        return HealthResponse(
            status="healthy",
            virustotal_api=vt_status,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        raise HTTPException(
            status_code=503,
            detail="Service unhealthy"
        )


# ====================== ROOT ENDPOINT ======================


@app.get("/")
async def root() -> Dict[str, Any]:
    """
    Root endpoint with API information.

    Returns:
        Dict with service status and available endpoints
    """
    return {
        "message": "✅ BharatCyber EduShield Backend Running",
        "status": "Ready",
        "version": "1.0.0",
        "endpoints": {
            "detect": "POST /detect - Scan for phishing threats",
            "history": "GET /scans/history - Retrieve scan history",
            "dpdp_logs": "GET /dpdp/logs - DPDP compliance logs",
            "admin_stats": "GET /admin/stats - Admin statistics",
            "health": "GET /health - Health check",
            "docs": "GET /docs - OpenAPI documentation",
            "redoc": "GET /redoc - ReDoc documentation"
        }
    }


# ====================== STARTUP EVENT ======================


@app.on_event("startup")
async def startup_event():
    """
    Startup event handler for application initialization.
    """
    logger.info("=" * 60)
    logger.info("🚀 BharatCyber EduShield Backend Starting")
    logger.info("=" * 60)

    if VT_API_KEY:
        logger.info("✅ VirusTotal API: Enabled")
    else:
        logger.warning(
            "⚠️ VirusTotal API: Disabled (set VIRUSTOTAL_API_KEY env var)"
        )

    logger.info(f"CORS Origins: {ALLOWED_ORIGINS}")
    logger.info("=" * 60)


# ====================== SHUTDOWN EVENT ======================


@app.on_event("shutdown")
async def shutdown_event():
    """
    Shutdown event handler for graceful cleanup.
    """
    logger.info("🛑 BharatCyber EduShield Backend Shutting Down")
    logger.info(f"Total scans in session: {len(scans_history)}")
    logger.info(f"Total DPDP logs in session: {len(dpdp_logs)}")
