import os
import json
import time
from datetime import datetime
from typing import Dict, List, Any

# MITRE ATT&CK Knowledge Base Mapping (Enterprise Linux Matrix)
MITRE_TECHNIQUES = {
    # Discovery (TA0007)
    "whoami": {"id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery", "weight": 10},
    "id": {"id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery", "weight": 10},
    "uname": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "weight": 10},
    "hostname": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "weight": 10},
    "ps": {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "weight": 15},
    "top": {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "weight": 10},
    "htop": {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "weight": 10},
    "netstat": {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery", "weight": 20},
    "ss": {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery", "weight": 20},
    "ifconfig": {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery", "weight": 15},
    "ip": {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery", "weight": 15},
    "ls": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "weight": 5},
    "find": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "weight": 15},

    # Credential Access (TA0006)
    "shadow": {"id": "T1003.008", "name": "OS Credential Dumping: /etc/shadow", "tactic": "Credential Access", "weight": 40},
    "passwd": {"id": "T1087.001", "name": "Account Discovery: Local Accounts", "tactic": "Discovery", "weight": 15},
    "history": {"id": "T1552.003", "name": "Unsecured Credentials: Bash History", "tactic": "Credential Access", "weight": 35},
    "credentials": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access", "weight": 40},
    ".aws": {"id": "T1552.001", "name": "Credentials In Files: Cloud Provider", "tactic": "Credential Access", "weight": 45},

    # Lateral Movement & Exfiltration (TA0008, TA0010)
    "curl": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "weight": 25},
    "wget": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "weight": 25},
    "scp": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "weight": 35},
    "ssh": {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement", "weight": 30},
    "nc": {"id": "T1095", "name": "Non-Application Layer Protocol (Netcat)", "tactic": "Command and Control", "weight": 35},
    "nmap": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "weight": 30}
}

# Deception Bait & Canary Strings
CANARY_TOKENS = [
    "AKIA_CANARY_TRAP_99",
    "AKIAIOSFODNN7CANARY1",
    "/root/.aws/credentials",
    "prod-db-backups-internal",
    "/etc/shadow"
]


class SessionTelemetry:
    def __init__(self, session_id: str, client_ip: str, client_port: int, username: str, password: str):
        self.session_id = session_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = username
        self.password = password
        self.start_time = datetime.utcnow().isoformat() + "Z"
        self.threat_score = 0
        self.severity = "LOW"
        self.canary_tripped = False
        self.canary_triggers: List[Dict[str, Any]] = []
        self.events: List[Dict[str, Any]] = []
        self.mitre_techniques_observed: Dict[str, Dict[str, str]] = {}

        # Ensure captures directory exists
        self.captures_dir = os.path.join(os.path.dirname(__file__), "captures")
        os.makedirs(self.captures_dir, exist_ok=True)
        self.log_file = os.path.join(self.captures_dir, f"{self.session_id}.json")
        self.save_to_disk()

    def analyze_command(self, raw_cmd: str, output: str) -> Dict[str, Any]:
        """
        Evaluates command against MITRE ATT&CK rules and Canary Tripwires.
        """
        cmd_lower = raw_cmd.lower()
        matched_techniques = []
        canary_alert = None

        # 1. MITRE ATT&CK Mapping
        for pattern, meta in MITRE_TECHNIQUES.items():
            if pattern in cmd_lower:
                matched_techniques.append(meta)
                self.threat_score = min(100, self.threat_score + meta["weight"])
                self.mitre_techniques_observed[meta["id"]] = {
                    "name": meta["name"],
                    "tactic": meta["tactic"]
                }

        # 2. Canary Tripwire Detection
        for token in CANARY_TOKENS:
            if token.lower() in cmd_lower or token.lower() in output.lower():
                self.canary_tripped = True
                self.threat_score = 100  # Instant critical threat
                canary_alert = {
                    "token_detected": token,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "trigger_command": raw_cmd
                }
                self.canary_triggers.append(canary_alert)
                break

        # 3. Calculate Severity Level
        if self.canary_tripped or self.threat_score >= 80:
            self.severity = "CRITICAL"
        elif self.threat_score >= 50:
            self.severity = "HIGH"
        elif self.threat_score >= 25:
            self.severity = "MEDIUM"
        else:
            self.severity = "LOW"

        # 4. Record Event
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "command": raw_cmd,
            "mitre_matches": matched_techniques,
            "canary_alert": canary_alert,
            "current_threat_score": self.threat_score,
            "current_severity": self.severity
        }
        self.events.append(event)
        self.save_to_disk()

        return {
            "matched_techniques": matched_techniques,
            "canary_alert": canary_alert,
            "threat_score": self.threat_score,
            "severity": self.severity
        }

    def save_to_disk(self):
        """
        Persists structured telemetry to JSON.
        """
        payload = {
            "session_id": self.session_id,
            "metadata": {
                "client_ip": self.client_ip,
                "client_port": self.client_port,
                "captured_credentials": {
                    "username": self.username,
                    "password": self.password
                },
                "start_time": self.start_time,
                "last_active": datetime.utcnow().isoformat() + "Z"
            },
            "threat_assessment": {
                "score": self.threat_score,
                "severity": self.severity,
                "canary_tripped": self.canary_tripped,
                "canary_triggers": self.canary_triggers,
                "unique_mitre_techniques": list(self.mitre_techniques_observed.values())
            },
            "event_timeline": self.events
        }

        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)