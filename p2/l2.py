import hashlib
import itertools
import string
import threading
import time
import csv
import os
from tkinter import Tk, StringVar, BooleanVar, IntVar, filedialog, messagebox, END
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

# ----------------------------- Utility functions -----------------------------

def hash_text(text: str, algo: str) -> str:
    t = text.encode("utf-8", errors="ignore")
    algo = algo.lower()
    if algo == "md5":
        return hashlib.md5(t).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(t).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(t).hexdigest()
    raise ValueError("Unsupported algorithm")

def detect_hash_algo(hexstr: str) -> str | None:
    s = hexstr.strip().lower()
    if all(c in string.hexdigits for c in s):
        if len(s) == 32:
            return "md5"
        if len(s) == 40:
            return "sha1"
        if len(s) == 64:
            return "sha256"
    return None

COMMON_WEAK = {
    "123456", "password", "qwerty", "111111", "letmein", "abc123", "12345678",
    "iloveyou", "admin", "welcome", "monkey", "dragon", "football", "login"
}

def password_strength(pw: str, dictionary_set: set[str] | None = None) -> tuple[str, float, list[str]]:
    reasons = []
    length = len(pw)
    variety = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in string.punctuation for c in pw),
    ])
    score = min(60, length * 4) + variety * 10
    if pw.lower() in COMMON_WEAK:
        score -= 30; reasons.append("in common weak list")
    if pw.isdigit() and length < 8:
        score -= 20; reasons.append("short digits-only")
    if dictionary_set and pw.lower() in dictionary_set:
        score -= 15; reasons.append("found in dictionary")
    score = max(0, min(100, score))
    if score < 40: cat = "Weak"
    elif score < 70: cat = "Medium"
    else: cat = "Strong"
    if not reasons:
        reasons.append({"Weak":"short or low variety","Medium":"ok but could be longer/more diverse","Strong":"good length and variety"}[cat])
    return cat, float(score), reasons

# ----------------------------- Attack controller -----------------------------

class AttackController:
    def __init__(self, log_callback, progress_callback, live_callback, done_callback):
        self.stop_event = threading.Event()
        self.log = log_callback
        self.progress = progress_callback
        self.live = live_callback          # <- NEW: live guess updater
        self.done = done_callback
        self.total = 0
        self.attempts = 0
        self.start_time = None

    def reset(self):
        self.stop_event.clear()
        self.total = 0
        self.attempts = 0
        self.start_time = time.time()

    def request_stop(self):
        self.stop_event.set()

    def should_stop(self):
        return self.stop_event.is_set()

# ----------------------------- Attack workers -----------------------------

def dict_attack(controller: AttackController, target: str, mode: str, algo: str, words: list[str]):
    controller.reset()
    controller.total = len(words)
    found = None
    for i, w in enumerate(words, 1):
        if controller.should_stop():
            controller.log("\n[!] Attack cancelled by user.")
            controller.done(None, cancelled=True); return
        w = w.strip("\r\n")
        controller.attempts = i
        # Live guess (throttled)
        if i % 50 == 0 or i == 1:
            controller.live(f"Trying: {w}")
        match = (w == target) if mode == 'plaintext' else (hash_text(w, algo) == target.lower())
        if i % 200 == 0 or i == controller.total:
            controller.progress(controller.attempts, controller.total)
        if match:
            found = w
            controller.log(f"[+] Found: '{w}' after {i} attempts")
            break
    if not found:
        controller.log("[-] No match in dictionary.")
    controller.done(found, cancelled=False)

def brute_force_attack(controller: AttackController, target: str, mode: str, algo: str,
                       charset: str, min_len: int, max_len: int):
    controller.reset()
    total = sum(len(charset) ** L for L in range(min_len, max_len + 1))
    controller.total = total
    attempts = 0
    for L in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=L):
            if controller.should_stop():
                controller.log("\n[!] Attack cancelled by user.")
                controller.done(None, cancelled=True); return
            cand = ''.join(combo)
            attempts += 1
            controller.attempts = attempts
            # Live guess (throttled)
            if attempts % 200 == 0 or attempts == 1:
                controller.live(f"Trying: {cand}")
            match = (cand == target) if mode == 'plaintext' else (hash_text(cand, algo) == target.lower())
            if attempts % 2000 == 0 or attempts == total:
                controller.progress(attempts, total)
            if match:
                controller.log(f"[+] Found: '{cand}' after {attempts} attempts")
                controller.progress(attempts, total)
                controller.done(cand, cancelled=False); return
    controller.log("[-] Not found in brute-force range.")
    controller.done(None, cancelled=False)

# --------------------------------- GUI ---------------------------------

class App:
    def __init__(self, root: Tk):
        self.root = root
        root.title("Dictionary & Brute-Force Password Demo (Educational)")
        root.geometry("980x740")

        self.controller = AttackController(
            log_callback=self.log,
            progress_callback=self.update_progress,
            live_callback=self.update_live_guess,     # <- NEW: live guess hook
            done_callback=self.on_done
        )

        # Vars
        self.mode = StringVar(value="hash")  # 'hash' or 'plaintext'
        self.hash_algo = StringVar(value="md5")
        self.target_input = StringVar()
        self.auto_detect = BooleanVar(value=True)

        self.charset_choice = StringVar(value="lower+digits")
        self.min_len = IntVar(value=1)
        self.max_len = IntVar(value=4)      # supports 4+; careful with big ranges

        self.words: list[str] = [
            "password","123456","qwerty","letmein","welcome","admin","iloveyou",
            "dragon","monkey","football","login","abc123"
        ]
        self.analysis_results = {"Weak": [], "Medium": [], "Strong": []}

        self._build_ui()

    # ---------- UI builders ----------
    def _build_ui(self):
        nb = ttk.Notebook(self.root); nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_attack = ttk.Frame(nb); self.tab_analyze = ttk.Frame(nb); self.tab_log = ttk.Frame(nb)
        nb.add(self.tab_attack, text="Attack")
        nb.add(self.tab_analyze, text="Analyze Passwords")
        nb.add(self.tab_log, text="Log & Export")
        self._build_attack_tab()
        self._build_analyze_tab()
        self._build_log_tab()

    def _build_attack_tab(self):
        frm = ttk.Frame(self.tab_attack); frm.pack(fill="x", padx=10, pady=10)

        # Target
        row1 = ttk.Frame(frm); row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Target (password or hash):").pack(side="left")
        ttk.Entry(row1, textvariable=self.target_input, width=70).pack(side="left", padx=6)
        ttk.Button(row1, text="Paste", command=self._paste).pack(side="left")
        ttk.Checkbutton(row1, text="Auto-detect hash algo", variable=self.auto_detect).pack(side="left", padx=6)

        # Mode & algo + Strength Check
        row2 = ttk.Frame(frm); row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Mode:").pack(side="left")
        ttk.Radiobutton(row2, text="Hash target", variable=self.mode, value="hash").pack(side="left")
        ttk.Radiobutton(row2, text="Plaintext target", variable=self.mode, value="plaintext").pack(side="left")
        ttk.Label(row2, text="Algorithm:").pack(side="left", padx=(20, 2))
        algo_combo = ttk.Combobox(row2, textvariable=self.hash_algo, values=["md5","sha1","sha256"], width=8)
        algo_combo.pack(side="left", padx=(0,10))
        ttk.Button(row2, text="Check Strength", command=self.check_strength_button).pack(side="left")

        # Dictionary controls
        dictf = ttk.LabelFrame(self.tab_attack, text="Dictionary Attack")
        dictf.pack(fill="x", padx=10, pady=6)
        ttk.Label(dictf, text=f"Loaded words: (default {len(self.words)}). You can load your own wordlist file.").pack(anchor="w", padx=8, pady=2)
        btns = ttk.Frame(dictf); btns.pack(fill="x", padx=6, pady=4)
        ttk.Button(btns, text="Load Wordlist...", command=self.load_wordlist).pack(side="left")
        ttk.Button(btns, text="Start Dictionary Attack", command=self.start_dict_attack).pack(side="left", padx=6)

        # Brute-force controls
        bf = ttk.LabelFrame(self.tab_attack, text="Brute-Force Attack (Simulation)")
        bf.pack(fill="x", padx=10, pady=6)
        ttk.Label(bf, text="Charset:").grid(row=0, column=0, sticky="w", padx=6, pady=3)
        ttk.Combobox(bf, textvariable=self.charset_choice, values=[
            "lower","digits","lower+digits","letters","letters+digits","letters+digits+symbols"
        ], width=24).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Label(bf, text="Min length:").grid(row=0, column=2, sticky="w", padx=6)
        ttk.Spinbox(bf, from_=1, to=8, textvariable=self.min_len, width=5).grid(row=0, column=3)
        ttk.Label(bf, text="Max length:").grid(row=0, column=4, sticky="w", padx=6)
        ttk.Spinbox(bf, from_=1, to=8, textvariable=self.max_len, width=5).grid(row=0, column=5)
        ttk.Button(bf, text="Start Brute-Force", command=self.start_brute_force).grid(row=0, column=6, padx=8)
        ttk.Button(bf, text="Cancel", command=self.cancel_attack).grid(row=0, column=7, padx=4)

        # Progress + live guess
        progf = ttk.LabelFrame(self.tab_attack, text="Progress")
        progf.pack(fill="x", padx=10, pady=8)
        self.progress_var = IntVar(value=0)
        self.progressbar = ttk.Progressbar(progf, orient="horizontal", length=600, mode="determinate", maximum=1000)
        self.progressbar.pack(fill="x", padx=8, pady=6)
        self.status_var = StringVar(value="Idle")
        ttk.Label(progf, textvariable=self.status_var).pack(anchor="w", padx=8)
        self.live_var = StringVar(value="")    # <- NEW live guess label
        ttk.Label(progf, textvariable=self.live_var, foreground="#555").pack(anchor="w", padx=8, pady=(2,6))

    def _build_analyze_tab(self):
        frm = ttk.Frame(self.tab_analyze); frm.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Label(frm, text="Analyze passwords from a file (one per line), then export by category:").pack(anchor="w")
        top = ttk.Frame(frm); top.pack(fill="x", pady=6)
        ttk.Button(top, text="Load Password List...", command=self.load_password_list).pack(side="left")
        ttk.Button(top, text="Export CSV", command=lambda: self.export_analysis("csv")).pack(side="left", padx=6)
        ttk.Button(top, text="Export TXT", command=lambda: self.export_analysis("txt")).pack(side="left")
        self.tree = ttk.Treeview(frm, columns=("password","category","score","notes"), show="headings")
        for col, w in (("password",260),("category",100),("score",80),("notes",360)):
            self.tree.heading(col, text=col.capitalize()); self.tree.column(col, width=w)
        self.tree.pack(fill="both", expand=True, pady=6)

    def _build_log_tab(self):
        frm = ttk.Frame(self.tab_log); frm.pack(fill="both", expand=True, padx=10, pady=10)
        self.logbox = ScrolledText(frm, height=22); self.logbox.pack(fill="both", expand=True)
        btns = ttk.Frame(frm); btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Save Log as TXT", command=self.save_log).pack(side="left")
        ttk.Button(btns, text="Clear Log", command=lambda: self.logbox.delete('1.0', END)).pack(side="left", padx=6)

    # ---------- Handlers ----------
    def _paste(self):
        try:
            self.target_input.set(self.root.clipboard_get())
        except Exception:
            pass

    def check_strength_button(self):
        target = self.target_input.get().strip()
        if not target:
            messagebox.showwarning("Input", "Enter a target first."); return
        if self.mode.get() == "hash":
            messagebox.showinfo("Strength", "Strength applies to plaintext.\nSwitch to 'Plaintext target' to evaluate."); return
        dict_set = set(w.lower() for w in self.words)
        cat, score, reasons = password_strength(target, dict_set)
        msg = f"Strength: {cat} (score {score:.0f})\n- " + "\n- ".join(reasons)
        self.status_var.set(f"Strength: {cat} (score {score:.0f})")
        self.log(msg)

    def load_wordlist(self):
        path = filedialog.askopenfilename(title="Choose wordlist", filetypes=[("Text","*.txt"),("All","*.*")])
        if not path: return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.words = [line.strip() for line in f if line.strip()]
            messagebox.showinfo("Wordlist", f"Loaded {len(self.words)} words.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load wordlist: {e}")

    def start_dict_attack(self):
        target = self.target_input.get().strip()
        if not target:
            messagebox.showwarning("Input", "Enter a target (hash or plaintext)."); return
        mode = self.mode.get()
        algo = self.hash_algo.get()
        if mode == 'hash' and self.auto_detect.get():
            guess = detect_hash_algo(target)
            if guess:
                algo = guess; self.hash_algo.set(guess)
                self.log(f"[i] Auto-detected hash algo: {guess}")
        self.status_var.set("Running dictionary attack...")
        self.progressbar['value'] = 0
        t = threading.Thread(target=dict_attack, args=(self.controller, target, mode, algo, list(self.words)), daemon=True)
        t.start()

    def start_brute_force(self):
        target = self.target_input.get().strip()
        if not target:
            messagebox.showwarning("Input", "Enter a target (hash or plaintext)."); return
        mode = self.mode.get()
        algo = self.hash_algo.get()
        min_len = int(self.min_len.get()); max_len = int(self.max_len.get())
        if min_len > max_len:
            messagebox.showwarning("Lengths", "Min length cannot exceed Max length."); return
        charset = self._charset_from_choice(self.charset_choice.get())
        combos = sum(len(charset) ** L for L in range(min_len, max_len + 1))
        if combos > 50_000_000:
            if not messagebox.askyesno("Warning", f"This will try ~{combos:,} combos. Continue?"):
                return
        self.status_var.set("Running brute-force...")
        self.progressbar['value'] = 0
        self.live_var.set("")
        t = threading.Thread(target=brute_force_attack, args=(self.controller, target, mode, algo, charset, min_len, max_len), daemon=True)
        t.start()

    def cancel_attack(self):
        self.controller.request_stop()

    def update_progress(self, attempts, total):
        frac = attempts / total if total else 0
        self.progressbar['value'] = int(frac * 1000)
        elapsed = time.time() - (self.controller.start_time or time.time())
        rate = attempts / elapsed if elapsed > 0 else 0
        eta = (total - attempts) / rate if rate > 0 else float('inf')
        eta_txt = "∞" if eta == float('inf') else f"{int(eta)}s"
        self.status_var.set(f"Attempts: {attempts:,}/{total:,}  |  Rate: {rate:,.0f}/s  |  ETA: {eta_txt}")
        self.root.update_idletasks()

    def update_live_guess(self, text: str):
        self.live_var.set(text)

    def on_done(self, found, cancelled=False):
        if cancelled:
            self.status_var.set("Cancelled")
        elif found:
            self.status_var.set(f"Found: {found}")
            self.live_var.set("")
        else:
            self.status_var.set("Finished: not found")

    def log(self, text: str):
        self.logbox.insert(END, text + "\n")
        self.logbox.see(END)

    def _charset_from_choice(self, choice: str) -> str:
        return {
            "lower": string.ascii_lowercase,
            "digits": string.digits,
            "lower+digits": string.ascii_lowercase + string.digits,
            "letters": string.ascii_letters,
            "letters+digits": string.ascii_letters + string.digits,
            "letters+digits+symbols": string.ascii_letters + string.digits + string.punctuation
        }.get(choice, string.ascii_lowercase)

    # -------- Password list analysis & export (Analyze tab) --------
    def load_password_list(self):
        path = filedialog.askopenfilename(title="Choose password list (one per line)", filetypes=[("Text","*.txt"),("CSV","*.csv"),("All","*.*")])
        if not path: return
        passwords = []
        try:
            if path.lower().endswith('.csv'):
                with open(path, newline='', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row: passwords.append(str(row[0]).strip())
            else:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}"); return
        dict_set = set(w.lower() for w in self.words)
        for c in self.tree.get_children(): self.tree.delete(c)
        self.analysis_results = {"Weak": [], "Medium": [], "Strong": []}
        for pw in passwords:
            cat, score, reasons = password_strength(pw, dict_set)
            notes = "; ".join(reasons)
            self.tree.insert('', END, values=(pw, cat, f"{score:.0f}", notes))
            self.analysis_results[cat].append({"password": pw, "score": score, "notes": notes})
        messagebox.showinfo("Analyze", f"Analyzed {len(passwords)} passwords.")

    def export_analysis(self, kind: str = "csv"):
        if kind not in {"csv","txt"}: return
        default_name = f"password_analysis.{kind}"
        path = filedialog.asksaveasfilename(defaultextension=f".{kind}", initialfile=default_name,
                                            filetypes=[("CSV","*.csv"),("Text","*.txt")])
        if not path: return
        try:
            if kind == "csv":
                with open(path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Category","Password","Score","Notes"])
                    for cat in ("Weak","Medium","Strong"):
                        for item in self.analysis_results[cat]:
                            writer.writerow([cat, item["password"], f"{item['score']:.0f}", item["notes"]])
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    for cat in ("Weak","Medium","Strong"):
                        f.write(f"[{cat}]\n")
                        for item in self.analysis_results[cat]:
                            f.write(f"- {item['password']}  (score {item['score']:.0f})  {item['notes']}\n")
                        f.write("\n")
            messagebox.showinfo("Export", f"Saved: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    # ---------------- Log export ----------------
    def save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="attack_log.txt", filetypes=[("Text","*.txt")])
        if not path: return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.logbox.get('1.0', END))
            messagebox.showinfo("Saved", f"Saved log to {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

# ------------------------------ Main ------------------------------

if __name__ == "__main__":
    root = Tk()
    try:
        root.call("tk", "scaling", 1.2)
        style = ttk.Style()
        if "vista" in style.theme_names(): style.theme_use("vista")
        elif "clam" in style.theme_names(): style.theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()
