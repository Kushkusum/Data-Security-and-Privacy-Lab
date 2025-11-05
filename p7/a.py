import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import datetime
import pyperclip

# --------------------------
# Hash functions
def hash_string(data: str):
    return {
        "MD5": hashlib.md5(data.encode()).hexdigest(),
        "SHA-1": hashlib.sha1(data.encode()).hexdigest(),
        "SHA-256": hashlib.sha256(data.encode()).hexdigest(),
        "SHA-512": hashlib.sha512(data.encode()).hexdigest()
    }

def hash_file(filepath: str):
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
        return {
            "MD5": hashlib.md5(file_data).hexdigest(),
            "SHA-1": hashlib.sha1(file_data).hexdigest(),
            "SHA-256": hashlib.sha256(file_data).hexdigest(),
            "SHA-512": hashlib.sha512(file_data).hexdigest()
        }
    except FileNotFoundError:
        return None

# --------------------------
# GUI Application
class HashToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Hash Generator & Verifier")
        self.root.geometry("700x500")

        tab_control = ttk.Notebook(root)
        self.string_tab = ttk.Frame(tab_control)
        self.file_tab = ttk.Frame(tab_control)
        self.batch_tab = ttk.Frame(tab_control)
        self.verify_tab = ttk.Frame(tab_control)

        tab_control.add(self.string_tab, text="String Hashing")
        tab_control.add(self.file_tab, text="File Hashing")
        tab_control.add(self.batch_tab, text="Batch Hashing")
        tab_control.add(self.verify_tab, text="Verify Hash")
        tab_control.pack(expand=1, fill="both")

        self.setup_string_tab()
        self.setup_file_tab()
        self.setup_batch_tab()
        self.setup_verify_tab()

    # -------------------------- String Hashing Tab
    def setup_string_tab(self):
        tk.Label(self.string_tab, text="Enter text to hash:", font=("Arial", 12)).pack(pady=10)
        self.string_entry = tk.Entry(self.string_tab, width=60)
        self.string_entry.pack(pady=5)
        tk.Button(self.string_tab, text="Generate Hash", command=self.generate_string_hash).pack(pady=10)
        self.string_result = tk.Text(self.string_tab, height=8, width=70)
        self.string_result.pack(pady=10)
    
    def generate_string_hash(self):
        text = self.string_entry.get().strip()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text.")
            return
        hashes = hash_string(text)
        self.string_result.delete("1.0", tk.END)
        for k, v in hashes.items():
            self.string_result.insert(tk.END, f"{k}: {v}   [Copy]\n")
        self.add_copy_buttons(self.string_result)

    # -------------------------- File Hashing Tab
    def setup_file_tab(self):
        tk.Button(self.file_tab, text="Select File", command=self.select_file).pack(pady=10)
        self.file_label = tk.Label(self.file_tab, text="No file selected")
        self.file_label.pack(pady=5)
        self.file_result = tk.Text(self.file_tab, height=8, width=70)
        self.file_result.pack(pady=10)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_label.config(text=os.path.basename(file_path))
            hashes = hash_file(file_path)
            if not hashes:
                messagebox.showerror("Error", "File not found.")
                return
            self.file_result.delete("1.0", tk.END)
            for k, v in hashes.items():
                self.file_result.insert(tk.END, f"{k}: {v}   [Copy]\n")
            self.add_copy_buttons(self.file_result)

    # -------------------------- Batch Hashing Tab
    def setup_batch_tab(self):
        tk.Button(self.batch_tab, text="Select Multiple Files", command=self.select_batch_files).pack(pady=10)
        self.batch_result = tk.Text(self.batch_tab, height=20, width=80)
        self.batch_result.pack(pady=10)
        tk.Button(self.batch_tab, text="Save Report", command=self.save_batch_report).pack(pady=5)

    def select_batch_files(self):
        file_paths = filedialog.askopenfilenames()
        if not file_paths:
            return
        self.batch_result.delete("1.0", tk.END)
        self.batch_hashes = []
        for f in file_paths:
            h = hash_file(f)
            if h:
                info = f"{os.path.basename(f)} | MD5: {h['MD5']} | SHA-256: {h['SHA-256']}\n"
                self.batch_result.insert(tk.END, info)
                self.batch_hashes.append((f, h))

    def save_batch_report(self):
        if not hasattr(self, 'batch_hashes') or not self.batch_hashes:
            messagebox.showwarning("No Data", "No batch data to save.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if save_path:
            with open(save_path, "w") as f:
                for file, h in self.batch_hashes:
                    f.write(f"{file} | MD5: {h['MD5']} | SHA-256: {h['SHA-256']}\n")
            messagebox.showinfo("Saved", f"Batch report saved to {save_path}")

    # -------------------------- Hash Verification Tab
    def setup_verify_tab(self):
        tk.Label(self.verify_tab, text="Enter hash value:", font=("Arial", 12)).pack(pady=5)
        self.verify_entry = tk.Entry(self.verify_tab, width=60)
        self.verify_entry.pack(pady=5)
        tk.Label(self.verify_tab, text="Select file to verify:", font=("Arial", 12)).pack(pady=5)
        tk.Button(self.verify_tab, text="Select File", command=self.verify_file_hash).pack(pady=5)
        self.verify_result = tk.Label(self.verify_tab, text="", font=("Arial", 12))
        self.verify_result.pack(pady=10)

    def verify_file_hash(self):
        hash_val = self.verify_entry.get().strip()
        if not hash_val:
            messagebox.showwarning("Input Error", "Please enter hash value.")
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        file_hashes = hash_file(file_path)
        if not file_hashes:
            messagebox.showerror("Error", "File not found.")
            return
        if hash_val in file_hashes.values():
            self.verify_result.config(text="✅ Hash MATCHES file.", fg="green")
        else:
            self.verify_result.config(text="❌ Hash does NOT match.", fg="red")

    # -------------------------- Utility to add copy buttons
    def add_copy_buttons(self, text_widget):
        def copy_to_clipboard(event):
            line = text_widget.get("insert linestart", "insert lineend").split(":")[1].split("[")[0].strip()
            pyperclip.copy(line)
            messagebox.showinfo("Copied", f"Copied: {line}")
        text_widget.bind("<Button-1>", copy_to_clipboard)

# -------------------------- MAIN
if __name__ == "__main__":
    root = tk.Tk()
    app = HashToolApp(root)
    root.mainloop()
