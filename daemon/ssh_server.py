import asyncio
import os
import sys
import uuid
import asyncssh
from dotenv import load_dotenv

# Ensure core & telemetry modules are importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.engine import ShellDeceptionEngine
from telemetry.analyzer import SessionTelemetry

load_dotenv()

SSH_BANNER = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"

# Active sessions repository
ACTIVE_SESSIONS = {}


class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self):
        self.peer_ip = "127.0.0.1"
        self.peer_port = 0
        self.session_id = str(uuid.uuid4())[:8]

    def connection_made(self, conn):
        peer = conn.get_extra_info('peername')
        if peer:
            self.peer_ip, self.peer_port = peer[0], peer[1]
        print(f"\n[!] INCOMING CONNECTION [{self.session_id}] from {self.peer_ip}:{self.peer_port}")

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        print(f"[+] CREDENTIAL CAPTURED [{self.session_id}] -> User: '{username}' | Password: '{password}' | IP: {self.peer_ip}")
        # Initialize structured session telemetry
        telemetry = SessionTelemetry(
            session_id=self.session_id,
            client_ip=self.peer_ip,
            client_port=self.peer_port,
            username=username,
            password=password
        )
        ACTIVE_SESSIONS[self.session_id] = telemetry
        return True


async def handle_client(process: asyncssh.SSHServerProcess):
    username = process.get_extra_info('username') or "root"
    peer = process.get_extra_info('peername')
    
    # Retrieve matching telemetry session (or create fallback)
    telemetry = None
    for sess in ACTIVE_SESSIONS.values():
        if sess.username == username:
            telemetry = sess
            break

    if not telemetry:
        session_id = str(uuid.uuid4())[:8]
        telemetry = SessionTelemetry(session_id, peer[0] if peer else "127.0.0.1", peer[1] if peer else 0, username, "None")
        ACTIVE_SESSIONS[session_id] = telemetry

    # Initialize deception engine in thread-safe manner
    engine = await asyncio.to_thread(ShellDeceptionEngine)
    engine.user = username

    welcome_motd = (
        "Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-40-generic x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/pro\r\n\r\n"
        "System information as of login:\r\n"
        "  System load:  0.15               Processes:             142\r\n"
        "  Usage of /:   34.2% of 48.29GB   Users logged in:       1\r\n"
        "  Memory usage: 22%                IPv4 address for eth0: 10.0.4.15\r\n\r\n"
        "Last login: Wed Aug 14 08:35:10 2024 from 10.0.4.2\r\n\r\n"
    )
    process.stdout.write(welcome_motd)

    while not process.stdin.at_eof():
        process.stdout.write(engine.get_prompt())
        try:
            line = await process.stdin.readline()
        except (asyncssh.TerminalSizeChanged, asyncio.CancelledError):
            continue
        except Exception:
            break

        if not line:
            break

        cmd = line.strip()
        if not cmd:
            continue

        # Execute command in background thread
        result = await asyncio.to_thread(engine.execute_command, cmd)
        
        if result.get("exit_session"):
            process.stdout.write("logout\r\nConnection to prod-db-internal-01 closed.\r\n")
            break

        output = result.get("output", "")
        
        # Telemetry Analysis (MITRE ATT&CK & Canary Check)
        analysis = telemetry.analyze_command(cmd, output)
        
        # Real-time SOC Console Alerts
        if analysis.get("canary_alert"):
            print(f"\n🚨 [CRITICAL CANARY TRIPWIRE TRIPPED!] Adversary accessed honeypot token: {analysis['canary_alert']['token_detected']}")
            print(f"🚨 Command: '{cmd}' | Threat Score: {analysis['threat_score']}/100 [{analysis['severity']}]")
        elif analysis.get("matched_techniques"):
            for tech in analysis["matched_techniques"]:
                print(f"[+] MITRE ATT&CK [{tech['id']} - {tech['name']}] detected | Threat Score: {analysis['threat_score']}/100 [{analysis['severity']}]")

        if output:
            formatted_output = output.replace("\r\n", "\n").replace("\n", "\r\n")
            process.stdout.write(formatted_output + "\r\n")

    process.exit(0)


async def start_honeypot_daemon(host="0.0.0.0", port=2222):
    key_dir = os.path.join(os.path.dirname(__file__), "keys")
    os.makedirs(key_dir, exist_ok=True)
    key_path = os.path.join(key_dir, "honeypot_rsa_key")

    if not os.path.exists(key_path):
        print("[*] Generating ephemeral RSA 2048 host key for SSH service...")
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(key_path)

    print(f"[*] Starting ShadowHoneypot SSH Daemon on {host}:{port}...")
    print(f"[*] Emulating: {SSH_BANNER}")
    print("[*] Real-Time MITRE ATT&CK Telemetry & Canary Tripwire: ACTIVE\n")

    server = await asyncssh.create_server(
        HoneypotSSHServer,
        host,
        port,
        server_host_keys=[key_path],
        server_version=SSH_BANNER,
        process_factory=handle_client,
        line_editor=True,
        encoding="utf-8"
    )

    print(f"[+] Honeypot ACTIVE! Ready to intercept adversaries on port {port}.\n")
    await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(start_honeypot_daemon())
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Stopping Honeypot SSH Daemon...")