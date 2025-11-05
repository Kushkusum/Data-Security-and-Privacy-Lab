import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import hashlib
import itertools
import string
import csv
import os

# ---------------- Password Strength Checker ---------------- #
def check_strength(password):
    strength = 0
    remarks = ""

    if len(password) >= 8:
        strength += 1
    if any(char.isdigit() for char in password):
        strength += 1
    if any(char.isupper() for char in password):
        strength += 1
    if any(char.islower() for char in password):
        strength += 1
    if any(char in string.punctuation for char in password):
        strength += 1

    if strength <= 2:
        remarks = "Weak"
    elif strength == 3 or strength == 4:
        remarks = "Medium"
    else:
        remarks = "Strong"

    return remarks

# ---------------- Hashing Function ---------------- #
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# ---------------- Dictionary Attack ---------------- #
def load_dictionary():
    global dictionary_words
    file_path = filedialog.askopenfilename(title="Select Dictionary File", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            dictionary_words = file.read().splitlines()
        status_var.set(f"Dictionary Loaded: {len(dictionary_words)} words")

def run_dictionary_attack():
    global dictionary_words, target_hash, found_password
    if not dictionary_words:
        status_var.set("No dictionary loaded!")
        return
    
    target_hash = entry_hash.get().strip()
    if not target_hash:
        status_var.set("Enter a hash value!")
        return

    status_var.set("Running Dictionary Attack...")
    root.update()

    for word in dictionary_words:
        if sha256_hash(word) == target_hash:
            status_var.set(f"Password Found: {word}")
            found_password = word
            return

    status_var.set("Dictionary Attack Failed: No match found.")

# ---------------- Brute-force Attack ---------------- #
def run_bruteforce_attack():
    global found_password
    target_hash = entry_hash.get().strip()
    if not target_hash:
        status_var.set("Enter a hash value!")
        return

    max_length = int(combo_length.get())
    charset = string.ascii_letters + string.digits + string.punctuation

    progress_bar["value"] = 0
    total_guesses = sum(len(charset) ** i for i in range(1, max_length + 1))
    guess_counter = 0

    status_var.set("Running Brute-force Attack...")
    root.update()

    for length in range(1, max_length + 1):
        for guess in itertools.product(charset, repeat=length):
            guess_word = ''.join(guess)
            guess_counter += 1

            # Update progress bar and live guess
            progress_bar["value"] = (guess_counter / total_guesses) * 100
            live_guess_var.set(f"Trying: {guess_word}")
            root.update_idletasks()

            if sha256_hash(guess_word) == target_hash:
                status_var.set(f"Password Found: {guess_word}")
                found_password = guess_word
                return
    
    status_var.set("Brute-force Attack Failed.")

# ---------------- Analyze Passwords ---------------- #
def analyze_passwords():
    global dictionary_words
    if not dictionary_words:
        status_var.set("Load dictionary first for analysis!")
        return

    categories = {"Weak": [], "Medium": [], "Strong": []}
    for word in dictionary_words:
        strength = check_strength(word)
        categories[strength].append(word)

    analysis_results.set(f"Weak: {len(categories['Weak'])}, Medium: {len(categories['Medium'])}, Strong: {len(categories['Strong'])}")
    return categories

# ---------------- Export Results ---------------- #
def export_results():
    categories = analyze_passwords()
    if not categories:
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV Files", ".csv"), ("Text Files", ".txt")])
    if not file_path:
        return

    ext = os.path.splitext(file_path)[1]
    if ext == ".csv":
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Passwords"])
            for cat, words in categories.items():
                writer.writerow([cat, ", ".join(words)])
    else:
        with open(file_path, "w", encoding="utf-8") as f:
            for cat, words in categories.items():
                f.write(f"{cat}:\n")
                f.write(", ".join(words) + "\n\n")

    status_var.set(f"Results exported to {file_path}")

# ---------------- GUI ---------------- #
root = tk.Tk()
root.title("Password Cracker (Dictionary + Brute-force)")
root.geometry("600x450")

dictionary_words = []
found_password = None

# Input field
tk.Label(root, text="Enter Password / Hash (SHA-256):").pack(pady=5)
entry_hash = tk.Entry(root, width=60)
entry_hash.pack()

# Strength checker
tk.Button(root, text="Check Strength", command=lambda: status_var.set(f"Strength: {check_strength(entry_hash.get())}")).pack(pady=5)

# Dictionary Attack
tk.Button(root, text="Load Dictionary", command=load_dictionary).pack(pady=5)
tk.Button(root, text="Run Dictionary Attack", command=run_dictionary_attack).pack(pady=5)

# Brute-force Attack
tk.Label(root, text="Max Brute-force Password Length:").pack(pady=5)
combo_length = ttk.Combobox(root, values=[4,5,6], width=5)
combo_length.set(4)
combo_length.pack()

tk.Button(root, text="Run Brute-force Attack", command=run_bruteforce_attack).pack(pady=5)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=5)

live_guess_var = tk.StringVar()
tk.Label(root, textvariable=live_guess_var).pack()

# Analysis + Export
tk.Button(root, text="Analyze Passwords", command=analyze_passwords).pack(pady=5)
tk.Button(root, text="Export Results", command=export_results).pack(pady=5)

# Status
status_var = tk.StringVar(value="Status: Waiting...")
tk.Label(root, textvariable=status_var, fg="blue").pack(pady=10)

analysis_results = tk.StringVar()
tk.Label(root, textvariable=analysis_results, fg="green").pack()

root.mainloop()