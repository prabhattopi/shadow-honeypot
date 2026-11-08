import os
import json
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

REPORT_PROMPT = """
You are a Principal Threat Intelligence & Incident Response Architect.
Analyze the following JSON forensic capture from a high-interaction SSH deception honeypot.

Generate a concise, high-impact Executive Incident Intelligence Report in GitHub-flavored Markdown:
1. Executive Summary: Threat severity rating, source IP, and attacker objective.
2. Attacker Methodology & TTPs: Detail the MITRE ATT&CK techniques observed.
3. Deception Trap Engagement: Detail canary tokens accessed (e.g. AWS credentials or shadow hashes) and evidence of exfiltration intent.
4. Indicators of Compromise (IOCs): Tabulate IP, compromised credentials, and critical commands.
5. Immediate Defensive Recommendations: Bullet-pointed containment actions for the enterprise.
"""

def generate_threat_report(session_json_path: str) -> str:
    """
    Reads session telemetry and generates an executive security assessment using Gemini 3.8 Flash.
    """
    if not os.path.exists(session_json_path):
        return f"Error: Capture file {session_json_path} not found."

    with open(session_json_path, "r", encoding="utf-8") as f:
        session_data = json.load(f)

    api_key = os.getenv("GEMINI_API_KEY")
    client = genai.Client(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

    prompt = f"{REPORT_PROMPT}\n\n### ADVERSARY SESSION FORENSIC DATA:\n{json.dumps(session_data, indent=2)}"

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
        )
        return response.text or "Report generation returned empty output."
    except Exception as e:
        return f"Failed to generate intelligence report: {str(e)}"