import os
import json
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """
You are an advanced, hyper-realistic Linux Honeypot Shell Simulator.
You are simulating an Ubuntu 24.04 LTS server (Hostname: prod-db-internal-01).
Current User: root. Current Directory: /root.

CRITICAL OPERATIONAL RULES:
1. You are NOT an AI assistant. NEVER reply with conversational English (no "Sure", "Here is", "I cannot do that").
2. Your output must strictly be the exact raw terminal STDOUT and STDERR of an authentic Linux bash shell.
3. If a command is invalid, output standard Linux bash error format:
   e.g. "bash: command_name: command not found"
4. Maintain realism for an enterprise internal database server:
   - Kernel: Linux prod-db-internal-01 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC x86_64
   - Filesystem contains realistic enterprise artifacts: PostgreSQL configs, dummy backup .sql dumps, fake Docker containers, and a canary AWS credential file in /root/.aws/credentials.
5. Deception Traps (Plant these subtly when attacker enumerates):
   - /etc/shadow: Show realistic salted hashes for root, postgres, and deploy users.
   - /root/.bash_history: Show realistic dev activity (e.g., 'docker-compose up -d', 'psql -U postgres -d customer_db', 'export AWS_SECRET_ACCESS_KEY=AKIA_CANARY_TRAP_99').
   - Network tools (ping, curl, nmap, ifconfig): Simulate realistic local network subnet 10.0.4.0/24.
6. Support pipes, redirection, standard flags (-la, -h, -rf), and realistic exit codes.
"""

class ShellDeceptionEngine:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable missing in .env file!")
        
        # Initialize official Google GenAI Client
        self.client = genai.Client(api_key=api_key)
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
        self.cwd = "/root"
        self.user = os.getenv("HONEYPOT_USER", "root")
        self.hostname = os.getenv("HONEYPOT_HOSTNAME", "prod-db-internal-01")
        
        # Configure low-latency thinking mode for Gemini 3.8
        try:
            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                thinking_config=types.ThinkingConfig(thinking_level="low")
            )
        except Exception:
            # Fallback for standard configuration
            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT
            )

        # Initialize multi-turn chat session
        self.chat = self.client.chats.create(
            model=self.model_name,
            config=config
        )

    def execute_command(self, raw_command: str) -> dict:
        """
        Processes attacker input command and returns simulated STDOUT/STDERR and updated prompt.
        """
        cmd = raw_command.strip()
        if not cmd:
            return {"output": "", "cwd": self.cwd, "prompt": self.get_prompt()}

        if cmd in ["exit", "logout"]:
            return {"output": "logout\n", "exit_session": True}

        prompt_query = f"[CWD: {self.cwd}] [USER: {self.user}] Command: `{cmd}`"
        
        try:
            response = self.chat.send_message(prompt_query)
            output = response.text or ""
            
            # Clean accidental markdown backticks if returned
            if output.startswith("```bash") or output.startswith("```"):
                lines = output.splitlines()
                if len(lines) >= 2 and lines[-1].startswith("```"):
                    output = "\n".join(lines[1:-1])
                elif len(lines) >= 1:
                    output = "\n".join(lines[1:])
                    
            # Basic state tracking for 'cd'
            if cmd.startswith("cd "):
                target = cmd.split(" ", 1)[1].strip()
                if target == "/" or target.startswith("/"):
                    self.cwd = target
                elif target == "..":
                    parts = self.cwd.rstrip("/").split("/")
                    self.cwd = "/".join(parts[:-1]) or "/"
                elif target == "~":
                    self.cwd = "/root" if self.user == "root" else f"/home/{self.user}"
                else:
                    self.cwd = f"{self.cwd.rstrip('/')}/{target}"

            return {
                "command": cmd,
                "output": output.rstrip("\n"),
                "cwd": self.cwd,
                "prompt": self.get_prompt(),
                "exit_session": False
            }
        except Exception as e:
            return {
                "command": cmd,
                "output": f"bash: input_error: {str(e)}",
                "cwd": self.cwd,
                "prompt": self.get_prompt(),
                "exit_session": False
            }

    def get_prompt(self) -> str:
        symbol = "#" if self.user == "root" else "$"
        cwd_display = "~" if self.cwd == "/root" else self.cwd
        return f"{self.user}@{self.hostname}:{cwd_display}{symbol} "