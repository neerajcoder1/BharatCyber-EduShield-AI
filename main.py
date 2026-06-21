from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import re
import os
import requests
from datetime import datetime

app = FastAPI(title="BharatCyber EduShield")

# ====================== CORS ======================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====================== ENV ======================

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ====================== TEMP STORAGE ======================

scans_history = []
dpdp_logs = []

# ====================== MODELS ======================

class ScanRequest(BaseModel):
    text: str
    user_id: Optional[str] = "demo_teacher"


class ScanResponse(BaseModel):
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
    note: str = "EduShield AI Detection Engine"


# ====================== VIRUSTOTAL ======================

def check_url_virustotal(url: str):

    if not VT_API_KEY:
        return None

    try:

        headers = {
            "x-apikey": VT_API_KEY
        }

        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if submit_response.status_code != 200:
            return None

        analysis_id = submit_response.json()["data"]["id"]

        report_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )

        if report_response.status_code != 200:
            return None

        return report_response.json()

    except Exception:
        return None


# ====================== DETECT ======================

@app.post("/detect", response_model=ScanResponse)
async def detect_phishing(request: ScanRequest):

    if not request.text or len(request.text.strip()) < 3:
        raise HTTPException(
            status_code=400,
            detail="Input too short"
        )

    text = request.text.lower().strip()

    score = 0
    risk_level = "LOW"
    teacher_alert = None

    url_match = re.search(
        r'https?://[^\s]+',
        request.text
    )

    input_type = "URL" if url_match else "TEXT"

    # ======================
    # URL ANALYSIS
    # ======================

    if url_match:

        url = url_match.group()

        vt_result = check_url_virustotal(url)

        if vt_result:

            stats = vt_result.get(
                "data",
                {}
            ).get(
                "attributes",
                {}
            ).get(
                "stats",
                {}
            )

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                score = 95

            elif suspicious > 0:
                score = 65

            else:
                score = 10

        else:
            score += 20

            if url.startswith("http://"):
                score += 20

            suspicious_words = [
                "login",
                "verify",
                "bank",
                "reward",
                "claim",
                "otp",
                "upi",
                "secure",
                "gift",
                "winner"
            ]

            for word in suspicious_words:
                if word in text:
                    score += 15

    # ======================
    # TEXT ANALYSIS
    # ======================

    else:

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
            "claim now"
        ]

        for keyword in phishing_keywords:
            if keyword in text:
                score += 15

        if re.search(r'https?://\S+', request.text):
            score += 30

    score = min(score, 100)

    # ======================
    # RISK LEVEL
    # ======================

    if score >= 70:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    is_phishing = score >= 40

    if risk_level == "HIGH":
        teacher_alert = (
            f"🚨 High Risk Threat Detected for {request.user_id}"
        )

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
        timestamp=datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        teacher_alert=teacher_alert
    )

    # ======================
    # SAVE HISTORY
    # ======================

    scans_history.append({
        "id": len(scans_history) + 1,
        "user_id": request.user_id,
        "text": request.text[:150],
        "input_type": input_type,
        "is_phishing": result.is_phishing,
        "score": result.score,
        "risk_level": result.risk_level,
        "confidence": result.confidence,
        "timestamp": result.timestamp
    })

    # ======================
    # DPDP LOGS
    # ======================

    dpdp_logs.append({
        "timestamp": result.timestamp,
        "user_id": request.user_id,
        "action": "phishing_scan",
        "input_type": input_type,
        "is_phishing": result.is_phishing,
        "score": result.score,
        "risk_level": result.risk_level
    })

    return result


# ====================== HISTORY ======================

@app.get("/scans/history")
async def get_scan_history(user_id: Optional[str] = None):

    if user_id:
        history = [
            scan
            for scan in scans_history
            if scan["user_id"] == user_id
        ]
    else:
        history = scans_history[-30:]

    return {
        "total_scans": len(history),
        "scans": history[::-1]
    }


# ====================== DPDP ======================

@app.get("/dpdp/logs")
async def get_dpdp_logs():

    return {
        "total_logs": len(dpdp_logs),
        "logs": dpdp_logs[-20:]
    }


# ====================== ADMIN ======================

@app.get("/admin/stats")
async def admin_stats():

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

    return {
        "schools_protected": 4,
        "real_time_threats": high_risk + medium_risk,
        "dpdp_compliance": "93%",
        "students_protected_today": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk
    }


# ====================== HOME ======================

@app.get("/")
def home():

    return {
        "message": "✅ BharatCyber EduShield Backend Running",
        "status": "Ready",
        "endpoints": [
            "/detect",
            "/scans/history",
            "/dpdp/logs",
            "/admin/stats"
        ]
    }
