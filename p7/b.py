import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import base64
import binascii
import codecs
import urllib.parse
import pyperclip  # pip install pyperclip
import string
import math

# -------------------------
# Safe obfuscation helpers
def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64_decode(s: str):
    try:
        return base64.b64decode(s).decode('utf-8')
    except Exception:
        return None

def hex_encode(s: str) -> str:
    return binascii.hexlify(s.encode('utf-8')).decode('utf-8')

def hex_decode(s: str):
    try:
        return binascii.unhexlify(s).decode('utf-8')
    except Exception:
        return None

def rot13(s: str) -> str:
    return codecs.decode(s, 'rot_13')

def xor_obfuscate(s: str, key: int) -> str:
    # return hex string of XORed bytes
    b = s.encode('utf-8')
    x = bytes([bb ^ key for bb in b])
    return binascii.hexlify(x).decode('utf-8')

def xor_deobfuscate_from_hex(hexstr: str, key: int):
    try:
        data = binascii.unhexlify(hexstr)
        x = bytes([bb ^ key for bb in data])
        return x.decode('utf-8', errors='replace')
    except Exception:
        return None

def url_encode(s: str) -> str:
    return urllib.parse.quote(s)

def url_decode(s: str) -> str:
    try:
        return urllib.parse.unquote(s)
    except Exception:
        return None

def whitespace_concat(s: str) -> str:
    # split into small pieces with random-ish splits (deterministic here)
    parts = [s[i:i+3] for i in range(0, len(s), 3)]
    # return pieces joined with " + " to mimic concatenation obfuscation
    return " + ".join([f"'{p}'" for p in parts])

def remove_concat_marks(s: str) -> str:
    # Try to join simple quoted parts like 'abc' + 'def'
    import re
    parts = re.findall(r"'([^']*)'", s)
    if parts:
        return "".join(parts)
    return None

# -------------------------
# Heuristics & detection helpers
def printable_ratio(s: str):
    if not s:
        return 0.0
    printable = sum(1 for c in s if c in string.printable)
    return printable / len(s)

def looks_like_base64(s: str):
    # base64 uses A-Z a-z 0-9 +/ and = padding; reasonable length multiple of 4
    import re
    s_stripped = s.strip()
    if len(s_stripped) % 4 != 0:
        return False
    return re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', s_stripped) is not None

def looks_like_hex(s: str):
    import re
    s_stripped = s.strip()
    return re.fullmatch(r'[0-9a-fA-F]+', s_stripped) is not None and len(s_stripped) % 2 == 0

def detection_score(s: str):
    # simple weighted heuristic; 0..100 (higher -> more likely obfuscated)
    score = 0.0
    pr = printable_ratio(s)
    if pr < 0.6:
        score += 30
    if looks_like_base64(s):
        score += 30
    if looks_like_hex(s):
        score += 20
    if '%' in s:
        score += 10
    if '\\x' in s or '0x' in s:
        score += 10
    # suspicious tokens commonly used in obfuscation wrappers
    for token in ['eval(', 'Function(', 'unescape(', 'atob(', 'btoa(']:
        if token in s:
            score += 10
    # clamp
    return int(min(100, score))

# -------------------------
# GUI
class ObfuscationExplorer:
    def __init__(self, root):
        self.root = root
        self.root.title("Obfuscation Explorer — Safe & Educational")
        self.root.geometry("1000x700")
        self._build_ui()

    def _build_ui(self):
        # Top: input and controls
        top_frame = tk.Frame(self.root, pady=8)
        top_frame.pack(fill='x')

        tk.Label(top_frame, text="Input text:", font=("Segoe UI", 11)).grid(row=0, column=0, sticky='w')
        self.input_box = tk.Text(top_frame, height=4, width=100, wrap='word', font=("Consolas", 11))
        self.input_box.grid(row=1, column=0, columnspan=6, padx=8, pady=6)

        tk.Button(top_frame, text="Clear", command=self.clear_input).grid(row=0, column=5, sticky='e', padx=6)
        tk.Button(top_frame, text="Load from File...", command=self.load_file).grid(row=0, column=4, sticky='e', padx=6)

        # Left: obfuscate actions
        left = tk.LabelFrame(self.root, text="Obfuscate (apply)", padx=8, pady=8)
        left.pack(side='left', fill='y', padx=10, pady=10)

        tk.Button(left, text="Base64 Encode", width=20, command=self.do_b64).pack(pady=4)
        tk.Button(left, text="Hex Encode", width=20, command=self.do_hex).pack(pady=4)
        tk.Button(left, text="ROT13", width=20, command=self.do_rot13).pack(pady=4)
        tk.Button(left, text="URL-Percent Encode", width=20, command=self.do_urlencode).pack(pady=4)

        xor_frame = tk.Frame(left)
        xor_frame.pack(pady=6)
        tk.Label(xor_frame, text="XOR key (0-255):").pack(side='left')
        self.xor_key_var = tk.IntVar(value=42)
        tk.Entry(xor_frame, width=4, textvariable=self.xor_key_var).pack(side='left', padx=4)
        tk.Button(xor_frame, text="XOR (hex output)", command=self.do_xor).pack(side='left', padx=6)

        tk.Button(left, text="Whitespace / concat obfuscation", command=self.do_concat).pack(pady=6)

        # Middle: outputs
        mid = tk.LabelFrame(self.root, text="Output / Results", padx=8, pady=8)
        mid.pack(side='left', fill='both', expand=True, padx=8, pady=10)

        tk.Label(mid, text="Last Obfuscated Output:", font=("Segoe UI", 10, "bold")).pack(anchor='w')
        self.output_box = tk.Text(mid, height=6, wrap='word', font=("Consolas", 11))
        self.output_box.pack(fill='x', pady=6)
        self.output_box.config(state='disabled')

        copy_btn = tk.Button(mid, text="Copy Output", command=self.copy_output)
        copy_btn.pack(anchor='e')

        # Right: deobfuscate tries
        right = tk.LabelFrame(self.root, text="Deobfuscate / Try decode", padx=8, pady=8)
        right.pack(side='right', fill='y', padx=10, pady=10)

        tk.Button(right, text="Try Base64 Decode", width=24, command=self.try_b64).pack(pady=4)
        tk.Button(right, text="Try Hex Decode", width=24, command=self.try_hex).pack(pady=4)
        tk.Button(right, text="Try ROT13", width=24, command=self.try_rot13).pack(pady=4)
        tk.Button(right, text="URL Decode", width=24, command=self.try_urldecode).pack(pady=4)

        tk.Label(right, text="Try XOR brute force (1-byte keys):").pack(pady=(8,0))
        tk.Button(right, text="Run XOR brute (show printable results)", width=28, command=self.try_xor_bruteforce).pack(pady=4)

        tk.Button(right, text="Try remove concat marks", width=28, command=self.try_remove_concat).pack(pady=6)

        # Bottom: detection, deobfuscation attempts log
        bottom = tk.LabelFrame(self.root, text="Detection & Deobfuscation Log", padx=8, pady=8)
        bottom.pack(fill='both', expand=True, padx=10, pady=(0,10))

        self.log_box = tk.Text(bottom, height=12, wrap='word', font=("Consolas", 11))
        self.log_box.pack(fill='both', expand=True)
        self.log_box.config(state='disabled')

        # initial tip
        self.log("Tip: Enter text above, click obfuscation buttons to see transformed output. Use 'Try ...' buttons to attempt deobfuscation.")

    # -------------------------
    # UI actions
    def clear_input(self):
        self.input_box.delete("1.0", tk.END)
        self.output_box.config(state='normal')
        self.output_box.delete("1.0", tk.END)
        self.output_box.config(state='disabled')
        self.log("Cleared input and output.")

    def load_file(self):
        path = filedialog.askopenfilename(title="Select file to load text from")
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()
            self.input_box.delete("1.0", tk.END)
            self.input_box.insert(tk.END, data)
            self.log(f"Loaded file: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load file: {e}")

    def _get_input(self):
        return self.input_box.get("1.0", tk.END).rstrip("\n")

    def _set_output(self, text):
        self.output_box.config(state='normal')
        self.output_box.delete("1.0", tk.END)
        self.output_box.insert(tk.END, text)
        self.output_box.config(state='disabled')

    def copy_output(self):
        out = self.output_box.get("1.0", tk.END).strip()
        if out:
            pyperclip.copy(out)
            self.log("Output copied to clipboard.")
        else:
            messagebox.showinfo("Nothing", "No output to copy.")

    def log(self, msg):
        self.log_box.config(state='normal')
        self.log_box.insert(tk.END, f"{msg}\n")
        self.log_box.see(tk.END)
        self.log_box.config(state='disabled')

    # -------------------------
    # Obfuscation actions
    def do_b64(self):
        s = self._get_input()
        if not s:
            messagebox.showwarning("Input needed", "Please enter text to obfuscate.")
            return
        out = b64_encode(s)
        self._set_output(out)
        self.log(f"[Base64] Encoded. Printable ratio {printable_ratio(out):.2f}. Detection score {detection_score(out)}")

    def do_hex(self):
        s = self._get_input()
        if not s:
            messagebox.showwarning("Input needed", "Please enter text to obfuscate.")
            return
        out = hex_encode(s)
        self._set_output(out)
        self.log(f"[Hex] Encoded. Length {len(out)}. Detection score {detection_score(out)}")

    def do_rot13(self):
        s = self._get_input()
        if not s:
            messagebox.showwarning("Input needed", "Please enter text to obfuscate.")
            return
        out = rot13(s)
        self._set_output(out)
        self.log("[ROT13] Applied.")

    def do_urlencode(self):
        s = self._get_input()
        if not s:
            messagebox.showwarning("Input needed", "Please enter text to obfuscate.")
            return
        out = url_encode(s)
        self._set_output(out)
        self.log("[URL-Percent] Encoded. Detection score %d" % detection_score(out))

    def do_xor(self):
        s = self._get_input()
        if not s:
            messagebox.showwarning("Input needed", "Please enter text to obfuscate.")
            return
        key = self.xor_key_var.get()
        if not (0 <= key <= 255):
            messagebox.showwarning("Key error", "XOR key must be 0-255")
            return
        out = xor_obfuscate(s, key)
        self._set_output(out)
        self.log(f"[XOR] Obfuscated with key {key}. Hex length {len(out)}. Try brute-force in Deobfuscate tab.")

    def do_concat(self):
        s = self._get_input()
        if not s:
            messagebox.showwarning("Input needed", "Please enter text to obfuscate.")
            return
        out = whitespace_concat(s)
        self._set_output(out)
        self.log("[Concat] Applied naive split+joint obfuscation.")

    # -------------------------
    # Deobfuscation tries
    def try_b64(self):
        s = self._get_input() or self.output_box.get("1.0", tk.END).strip()
        if not s:
            messagebox.showwarning("Input needed", "Please enter or produce some text to try decoding.")
            return
        if not looks_like_base64(s):
            self.log("[Base64] Input does not look like canonical base64. Still attempting decode...")
        res = b64_decode(s)
        if res is None:
            self.log("[Base64] decode failed or produced non-text.")
        else:
            self.log("[Base64] Success. Result preview:\n" + res[:100])

    def try_hex(self):
        s = self._get_input() or self.output_box.get("1.0", tk.END).strip()
        if not s:
            messagebox.showwarning("Input needed", "Please enter or produce some text to try decoding.")
            return
        if not looks_like_hex(s):
            self.log("[Hex] Input doesn't look like pure hex; still attempting decode...")
        res = hex_decode(s)
        if res is None:
            self.log("[Hex] decode failed.")
        else:
            self.log("[Hex] Success. Result preview:\n" + res[:200])

    def try_rot13(self):
        s = self._get_input() or self.output_box.get("1.0", tk.END).strip()
        if not s:
            messagebox.showwarning("Input needed", "Please enter or produce some text to try ROT13.")
            return
        self.log("[ROT13] Result preview:\n" + rot13(s)[:200])

    def try_urldecode(self):
        s = self._get_input() or self.output_box.get("1.0", tk.END).strip()
        if not s:
            messagebox.showwarning("Input needed", "Please enter or produce some text to try URL decode.")
            return
        res = url_decode(s)
        if res is None:
            self.log("[URLDecode] decode failed.")
        else:
            self.log("[URLDecode] Result preview:\n" + res[:200])

    def try_xor_bruteforce(self):
        s = self._get_input() or self.output_box.get("1.0", tk.END).strip()
        if not s:
            messagebox.showwarning("Input needed", "Please enter hex text (XORed output) to try brute force.")
            return
        if not looks_like_hex(s):
            self.log("[XOR Bruteforce] Input does not look like hex — convert to hex first or select XOR output.")
            # still attempt by treating raw bytes
        candidates = []
        for key in range(0, 256):
            try:
                out = xor_deobfuscate_from_hex(s, key)
                # consider "likely readable" if printable ratio > 0.8 and has a space
                pr = printable_ratio(out)
                if pr > 0.8 and ' ' in out:
                    candidates.append((key, out[:200]))
            except Exception:
                continue
        if not candidates:
            self.log("[XOR Bruteforce] No high-confidence plaintext candidates found (showing low-confidence attempts):")
            # show some attempts
            for key in range(0, 10):
                out = xor_deobfuscate_from_hex(s, key)
                if out is not None:
                    self.log(f" key={key}: {out[:120]}")
        else:
            self.log("[XOR Bruteforce] Found plausible candidates:")
            for key, out in candidates[:8]:
                self.log(f" key={key}: {out}")

    def try_remove_concat(self):
        s = self._get_input() or self.output_box.get("1.0", tk.END).strip()
        if not s:
            messagebox.showwarning("Input needed", "Please enter or produce some text to try concat removal.")
            return
        res = remove_concat_marks(s)
        if res:
            self.log("[Concat removal] Success. Result:\n" + res[:200])
        else:
            self.log("[Concat removal] No simple quoted parts found.")

# -------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = ObfuscationExplorer(root)
    root.mainloop()
