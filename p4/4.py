import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import re

# -------------------------
# Define patterns with severity
vuln_patterns = {
    "Use of eval()": {"pattern": r"\beval\(", "severity": "Critical", "suggestion": "Use ast.literal_eval() instead"},
    "Use of exec()": {"pattern": r"\bexec\(", "severity": "Critical", "suggestion": "Avoid using exec()"},
    "Hardcoded password": {"pattern": r"(password|passwd|secret|apikey)\s*=\s*['\"].+['\"]",
                           "severity": "High", "suggestion": "Use environment variables or config files"},
    "SQL Injection Risk": {"pattern": r"(SELECT|INSERT|UPDATE|DELETE).*\+.*['\"]",
                           "severity": "Medium", "suggestion": "Use parameterized queries"},
    "Use of os.system": {"pattern": r"os\.system\(", "severity": "High", "suggestion": "Use subprocess with sanitization"},
    "Use of subprocess without sanitization": {"pattern": r"subprocess\.(call|Popen|run)\(", "severity": "High",
                                               "suggestion": "Ensure proper sanitization"},
}

supported_extensions = ['.py', '.js', '.php', '.java', '.c', '.cpp', '.rb']

# -------------------------
def scan_code(file_path):
    vulnerabilities_found = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        return []

    for i, line in enumerate(lines, start=1):
        for vuln, info in vuln_patterns.items():
            if re.search(info["pattern"], line, re.IGNORECASE):
                # Get context lines (2 before, 2 after)
                start = max(0, i-3)
                end = min(len(lines), i+2)
                context = "".join(lines[start:end]).strip()
                vulnerabilities_found.append({
                    "file": file_path,
                    "line": i,
                    "type": vuln,
                    "severity": info["severity"],
                    "code": line.strip(),
                    "context": context,
                    "suggestion": info["suggestion"]
                })
    return vulnerabilities_found

def scan_directory(directory):
    all_vulnerabilities = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in supported_extensions):
                file_path = os.path.join(root, file)
                vulns = scan_code(file_path)
                all_vulnerabilities.extend(vulns)
    return all_vulnerabilities

# -------------------------
# GUI
class VulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡 Vulnerability Analyzer Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg="#0f1724")

        # Top controls
        control_frame = tk.Frame(root, bg="#091025", pady=10)
        control_frame.pack(fill='x')

        tk.Label(control_frame, text="Vulnerability Analyzer", bg="#091025", fg="#9ecbff",
                 font=("Segoe UI", 16, "bold")).pack(side='left', padx=10)

        tk.Button(control_frame, text="Scan File", command=self.select_file,
                  bg="#10b981", fg="#fff", font=("Segoe UI", 11, "bold")).pack(side='left', padx=10)
        tk.Button(control_frame, text="Scan Directory", command=self.select_directory,
                  bg="#3b82f6", fg="#fff", font=("Segoe UI", 11, "bold")).pack(side='left', padx=10)
        tk.Button(control_frame, text="Clear Results", command=self.clear_results,
                  bg="#ef4444", fg="#fff", font=("Segoe UI", 11, "bold")).pack(side='left', padx=10)

        # Scrollable frame for results
        self.canvas = tk.Canvas(root, bg="#071020")
        self.scroll_frame = tk.Frame(self.canvas, bg="#071020")
        self.scrollbar = tk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        self.canvas.create_window((0, 0), window=self.scroll_frame, anchor='nw')
        self.scroll_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

    def clear_results(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

    def display_vulnerability(self, vuln):
        # Each vulnerability in its own frame
        frame = tk.LabelFrame(self.scroll_frame, text=f"{vuln['severity']} - {vuln['type']}", 
                              bg="#0b1220", fg="#f0f0f0", font=("Segoe UI", 10, "bold"), padx=8, pady=8)
        frame.pack(fill='x', padx=10, pady=6)

        tk.Label(frame, text=f"File: {vuln['file']}", bg="#0b1220", fg="#a5f3fc", anchor='w', font=("Segoe UI", 10, "bold")).pack(fill='x')
        tk.Label(frame, text=f"Line: {vuln['line']}", bg="#0b1220", fg="#a5f3fc").pack(anchor='w')
        tk.Label(frame, text=f"Code: {vuln['code']}", bg="#0b1220", fg="#ffedd5").pack(anchor='w')
        tk.Label(frame, text="Context:", bg="#0b1220", fg="#c7d2fe", font=("Segoe UI", 9, "italic")).pack(anchor='w', pady=(4,0))
        ctx_box = scrolledtext.ScrolledText(frame, height=5, bg="#020202", fg="#f9f5ff", font=("Consolas", 10))
        ctx_box.insert(tk.END, vuln['context'])
        ctx_box.configure(state='disabled')
        ctx_box.pack(fill='x', pady=2)
        tk.Label(frame, text=f"Suggestion: {vuln['suggestion']}", bg="#0b1220", fg="#6ee7b7", font=("Segoe UI", 9, "italic")).pack(anchor='w', pady=(2,0))

    def scan_and_display(self, path):
        self.clear_results()
        if os.path.isfile(path):
            results = scan_code(path)
        else:
            results = scan_directory(path)
        
        if results:
            for vuln in results:
                self.display_vulnerability(vuln)
        else:
            messagebox.showinfo("Scan Complete", "No vulnerabilities found!")

    def select_file(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.scan_and_display(path)

    def select_directory(self):
        path = filedialog.askdirectory(title="Select a directory")
        if path:
            self.scan_and_display(path)

# -------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerGUI(root)
    root.mainloop()
