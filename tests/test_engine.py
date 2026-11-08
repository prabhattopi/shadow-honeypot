import sys
import os

# Include parent dir
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.engine import ShellDeceptionEngine

def main():
    print("==========================================================")
    print("  SHADOW-HONEYPOT: AI SHELL ENGINE TESTER (GEMINI 2.5)")
    print("==========================================================")
    print("[*] Initializing Gemini 2.5 Flash shell environment...")
    
    try:
        engine = ShellDeceptionEngine()
        print("[+] Engine connected successfully!")
        print("[*] Type commands like an attacker (e.g., 'whoami', 'uname -a', 'ls -la', 'cat /etc/shadow', 'history').")
        print("[*] Type 'exit' to quit.\n")
    except Exception as e:
        print(f"[-] Initialization Failed: {e}")
        return

    while True:
        try:
            cmd = input(engine.get_prompt())
            if not cmd.strip():
                continue
            
            result = engine.execute_command(cmd)
            
            if result.get("exit_session"):
                print("[*] Connection closed by foreign host.")
                break
                
            if result["output"]:
                print(result["output"])
                
        except KeyboardInterrupt:
            print("\n[*] Exiting...")
            break
        except Exception as err:
            print(f"[-] Execution Error: {err}")

if __name__ == "__main__":
    main()