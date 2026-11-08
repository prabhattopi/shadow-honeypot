import os
import sys
import json
import glob
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Include root dir
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from telemetry.reporter import generate_threat_report

app = FastAPI(title="ShadowHoneypot SOC Command Center")

CAPTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "telemetry", "captures"))

# Active WebSocket subscribers
CONNECTED_CLIENTS = set()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    CONNECTED_CLIENTS.add(websocket)
    try:
        while True:
            # Keep-alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        CONNECTED_CLIENTS.remove(websocket)

@app.get("/api/sessions")
def list_sessions():
    """Lists all captured attack sessions."""
    if not os.path.exists(CAPTURES_DIR):
        return []
    
    files = glob.glob(os.path.join(CAPTURES_DIR, "*.json"))
    sessions = []
    for f in sorted(files, key=os.path.getmtime, reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as jf:
                data = json.load(jf)
                sessions.append({
                    "session_id": data.get("session_id"),
                    "ip": data.get("metadata", {}).get("client_ip"),
                    "threat_score": data.get("threat_assessment", {}).get("score", 0),
                    "severity": data.get("threat_assessment", {}).get("severity", "LOW"),
                    "canary_tripped": data.get("threat_assessment", {}).get("canary_tripped", False),
                    "start_time": data.get("metadata", {}).get("start_time"),
                    "events_count": len(data.get("event_timeline", []))
                })
        except Exception:
            continue
    return sessions

@app.get("/api/session/{session_id}")
def get_session_details(session_id: str):
    """Returns raw telemetry of a specific session."""
    filepath = os.path.join(CAPTURES_DIR, f"{session_id}.json")
    if not os.path.exists(filepath):
        return JSONResponse(status_code=404, content={"error": "Session not found"})
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/api/report/{session_id}")
def get_ai_incident_report(session_id: str):
    """Generates Gemini 3.8 Flash Threat Intel Report for this session."""
    filepath = os.path.join(CAPTURES_DIR, f"{session_id}.json")
    if not os.path.exists(filepath):
        return JSONResponse(status_code=404, content={"error": "Session not found"})
    report_md = generate_threat_report(filepath)
    return {"session_id": session_id, "report_markdown": report_md}

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    dashboard_html_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(dashboard_html_path, "r", encoding="utf-8") as f:
        return f.read()