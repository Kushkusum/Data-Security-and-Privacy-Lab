# vulnerable_sample.py
# Intentionally insecure examples for testing a static analyzer.
# DO NOT use these patterns in production code.

import os
import subprocess
import sqlite3
import ast
import yaml  # used only as an example comment; avoid yaml.load on untrusted input
import pickle

# ------------------------------
# 1) Use of eval()
# Vulnerability: executing untrusted input as code
# Detection pattern: \beval\(
def risky_eval(user_input):
    # BAD: executes whatever string is passed
    result = eval(user_input)    # <- flagged: Use of eval()
    return result

# Safe alternative (example): use ast.literal_eval for simple literals
def safe_eval(user_input):
    try:
        return ast.literal_eval(user_input)
    except Exception:
        return None

# ------------------------------
# 2) Use of exec()
# Vulnerability: executes arbitrary code strings
# Detection pattern: \bexec\(
def risky_exec(code_str):
    # BAD: runs arbitrary code
    exec(code_str)  # <- flagged: Use of exec()
    return "executed"

# Safe alternative: avoid exec; implement controlled logic or mapping

# ------------------------------
# 3) Hardcoded password / secret
# Detection pattern: (password|passwd|secret|apikey)\s*=\s*['"].+['"]
password = "P@ssw0rd123"         # <- flagged: Hardcoded password
apikey = "AK-EXAMPLE-KEY-12345"  # <- flagged: Hardcoded secret

# Safer: load from environment/config (example - not executed here)
# import os
# password = os.environ.get("MY_APP_PASSWORD")

# ------------------------------
# 4) SQL injection risk via string concatenation
# Detection pattern: (SELECT|INSERT|UPDATE|DELETE).*\+.*['"]
def get_user_by_id_unsafe(user_id):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    # BAD: building SQL by concatenation — vulnerable to injection
    query = "SELECT * FROM users WHERE id = " + user_id   # <- flagged: SQL Injection Risk
    cur.execute(query)
    return cur.fetchall()

# Safe alternative: parameterized queries
def get_user_by_id_safe(user_id):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()

# ------------------------------
# 5) Use of os.system()
# Detection pattern: os\.system\(
def dangerous_system_call(user_input):
    # BAD: directly passes user input to shell
    os.system("ls " + user_input)  # <- flagged: Use of os.system()

# Safer: use subprocess with argument list (and sanitize inputs)
def safer_subprocess_list(user_input):
    subprocess.run(["ls", user_input])

# ------------------------------
# 6) Use of subprocess without sanitization
# Detection pattern: subprocess\.(call|Popen|run)\(
def dangerous_subprocess(user_input):
    # BAD: forming a shell string (if shell=True or concatenating)
    subprocess.call("grep " + user_input + " /var/log/syslog", shell=True)  # <- flagged: Use of subprocess without sanitization

# Safer: pass args as list and avoid shell=True
def safer_subprocess(user_input):
    subprocess.run(["grep", user_input, "/var/log/syslog"], shell=False)

# ------------------------------
# Extra (educational) insecure patterns not in your scanner but common:
# - insecure deserialization (pickle.loads) — do NOT unpickle untrusted input
# - yaml.load (without SafeLoader) — prefer yaml.safe_load
insecure_serialized = pickle.dumps({"k":"v"})
def insecure_unpickle(data):
    # BAD: unpickling untrusted data can execute arbitrary code
    obj = pickle.loads(data)   # (educational example)
    return obj

def insecure_yaml_load(yaml_str):
    # BAD: yaml.load can execute tags; prefer yaml.safe_load
    return yaml.load(yaml_str)  # DO NOT use on untrusted input

# ------------------------------
# Example main function that demonstrates each snippet (kept safe by not executing user inputs)
def main():
    print("Demo file containing intentionally insecure patterns.")
    # NOTE: we won't execute the risky functions with real untrusted data here.
    # They exist only for static analysis / detection tests.
    sample_input = "'2 + 2'"             # for eval/ast demo
    print("safe_eval:", safe_eval(sample_input))

    # Showing hardcoded secret for scanner detection (no real secret present)
    print("Hardcoded password example variable:", password)

if __name__ == "__main__":
    main()
