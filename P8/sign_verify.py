import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
import os
import pyperclip

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# --------------------------
# RSA helpers (cryptography)
def generate_rsa_keypair(key_size=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    return priv, pub

def private_key_to_pem(private_key, password: bytes = None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_private_key_from_pem(pem_bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)

def load_public_key_from_pem(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

def sign_bytes(private_key, data: bytes, hash_algo=hashes.SHA256()):
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=padding.PSS.MAX_LENGTH),
        hash_algo
    )
    return signature

def verify_bytes(public_key, signature: bytes, data: bytes, hash_algo=hashes.SHA256()):
    public_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=padding.PSS.MAX_LENGTH),
        hash_algo
    )

# --------------------------
# GUI App
class RSASignTool:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Digital Signature Tool — Generate & Verify")
        self.root.geometry("820x620")
        self.private_key = None
        self.public_key = None

        # Top frame: key generation and load/save
        top = tk.Frame(root, pady=8)
        top.pack(fill='x')

        gframe = tk.LabelFrame(top, text="Key Management", padx=8, pady=8)
        gframe.pack(fill='x', padx=8, pady=4)

        tk.Label(gframe, text="Key size:", width=10).grid(row=0, column=0, sticky='w')
        self.keysize_var = tk.IntVar(value=2048)
        ttk.Combobox(gframe, textvariable=self.keysize_var, values=[2048, 3072, 4096], width=8).grid(row=0, column=1, sticky='w')

        tk.Button(gframe, text="Generate Key Pair", command=self.generate_keys, bg="#10b981", fg="white").grid(row=0, column=2, padx=8)
        tk.Button(gframe, text="Save Private Key", command=self.save_private_key).grid(row=0, column=3, padx=8)
        tk.Button(gframe, text="Save Public Key", command=self.save_public_key).grid(row=0, column=4, padx=8)
        tk.Button(gframe, text="Load Private Key", command=self.load_private_key).grid(row=0, column=5, padx=8)
        tk.Button(gframe, text="Load Public Key", command=self.load_public_key).grid(row=0, column=6, padx=8)

        # Hash selection
        tk.Label(gframe, text="Hash:", width=8).grid(row=1, column=0, sticky='w', pady=(6,0))
        self.hash_var = tk.StringVar(value="SHA256")
        ttk.Combobox(gframe, textvariable=self.hash_var, values=["SHA256","SHA384","SHA512"], width=10).grid(row=1, column=1, sticky='w', pady=(6,0))

        # Middle: signing panel & verification panel side-by-side
        mid = tk.Frame(root)
        mid.pack(fill='both', expand=True, padx=8, pady=6)

        # Sign frame
        sign_frame = tk.LabelFrame(mid, text="Sign — create a signature", padx=8, pady=8)
        sign_frame.pack(side='left', fill='both', expand=True, padx=6, pady=6)

        tk.Label(sign_frame, text="Text to sign:").pack(anchor='w')
        self.sign_text = tk.Text(sign_frame, height=8, font=("Consolas", 10))
        self.sign_text.pack(fill='x', pady=4)

        tk.Label(sign_frame, text="Or choose a file to sign:").pack(anchor='w', pady=(6,0))
        fbtn = tk.Button(sign_frame, text="Select file to sign", command=self.select_file_to_sign)
        fbtn.pack(anchor='w', pady=4)

        btn_row = tk.Frame(sign_frame)
        btn_row.pack(fill='x', pady=6)
        tk.Button(btn_row, text="Sign (Text/File)", command=self.sign_action, bg="#2563eb", fg="white").pack(side='left', padx=4)
        tk.Button(btn_row, text="Copy Signature", command=self.copy_signature).pack(side='left', padx=4)
        tk.Button(btn_row, text="Save Signature", command=self.save_signature).pack(side='left', padx=4)
        tk.Button(btn_row, text="Clear", command=self.clear_sign_inputs).pack(side='left', padx=4)

        tk.Label(sign_frame, text="Signature (base64):").pack(anchor='w', pady=(6,0))
        self.signature_box = tk.Text(sign_frame, height=6, font=("Consolas", 10))
        self.signature_box.pack(fill='both', expand=True, pady=4)

        # Verify frame
        verify_frame = tk.LabelFrame(mid, text="Verify — verify a signature", padx=8, pady=8)
        verify_frame.pack(side='right', fill='both', expand=True, padx=6, pady=6)

        tk.Label(verify_frame, text="Text to verify:").pack(anchor='w')
        self.verify_text = tk.Text(verify_frame, height=8, font=("Consolas", 10))
        self.verify_text.pack(fill='x', pady=4)

        tk.Label(verify_frame, text="Or choose a file to verify:").pack(anchor='w', pady=(6,0))
        tk.Button(verify_frame, text="Select file to verify", command=self.select_file_to_verify).pack(anchor='w', pady=4)

        tk.Label(verify_frame, text="Signature (base64):").pack(anchor='w', pady=(6,0))
        self.verify_sig_entry = tk.Entry(verify_frame, width=70)
        self.verify_sig_entry.pack(fill='x', pady=4)

        vbtn_row = tk.Frame(verify_frame)
        vbtn_row.pack(fill='x', pady=6)
        tk.Button(vbtn_row, text="Verify", command=self.verify_action, bg="#ef4444", fg="white").pack(side='left', padx=4)
        tk.Button(vbtn_row, text="Paste Sig (clipboard)", command=self.paste_signature).pack(side='left', padx=4)
        tk.Button(vbtn_row, text="Clear", command=self.clear_verify_inputs).pack(side='left', padx=4)

        self.verify_result_label = tk.Label(verify_frame, text="Result: -", font=("Arial", 12))
        self.verify_result_label.pack(pady=8)

        # Bottom: status & info
        bottom = tk.LabelFrame(root, text="Status & Info", padx=8, pady=8)
        bottom.pack(fill='x', padx=8, pady=(0,8))
        self.status_text = tk.Label(bottom, text="No keys loaded. Generate or load keys to start.", anchor='w', justify='left')
        self.status_text.pack(fill='x')

        # internal variables for selected file paths
        self.file_to_sign = None
        self.file_to_verify = None
        self.last_signature_bytes = None

    # ------------------- Key functions -------------------
    def generate_keys(self):
        k = self.keysize_var.get()
        if k not in (2048, 3072, 4096):
            messagebox.showwarning("Key size", "Choose 2048, 3072 or 4096")
            return
        self.status("Generating RSA key pair (this may take a moment)...")
        try:
            priv, pub = generate_rsa_keypair(key_size=k)
            self.private_key = priv
            self.public_key = pub
            self.status(f"Generated RSA key pair ({k} bits).")
            messagebox.showinfo("Success", f"Generated RSA key pair ({k} bits). You can save the keys.")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")
            self.status("Key generation failed.")

    def save_private_key(self):
        if not self.private_key:
            messagebox.showwarning("No key", "No private key loaded or generated.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files","*.pem"),("All files","*.*")])
        if not path:
            return
        # optional password prompt (simple)
        if messagebox.askyesno("Encrypt?", "Encrypt the private key with a password?"):
            pwd = tk.simpledialog.askstring("Password", "Enter password to encrypt private key:", show='*')
            if pwd is None:
                return
            pem = private_key_to_pem(self.private_key, password=pwd.encode())
        else:
            pem = private_key_to_pem(self.private_key, password=None)
        with open(path, "wb") as f:
            f.write(pem)
        self.status(f"Private key saved to {path}")

    def save_public_key(self):
        if not self.public_key:
            messagebox.showwarning("No key", "No public key loaded or generated.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files","*.pem"),("All files","*.*")])
        if not path:
            return
        pem = public_key_to_pem(self.public_key)
        with open(path, "wb") as f:
            f.write(pem)
        self.status(f"Public key saved to {path}")

    def load_private_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files","*.pem"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            # ask whether encrypted
            if b"ENCRYPTED" in data:
                pwd = tk.simpledialog.askstring("Password", "Enter password to decrypt private key:", show='*')
                if pwd is None:
                    return
                key = load_private_key_from_pem(data, password=pwd.encode())
            else:
                key = load_private_key_from_pem(data, password=None)
            self.private_key = key
            self.public_key = key.public_key()
            self.status(f"Loaded private key from {path}")
            messagebox.showinfo("Success", "Private key loaded. Public key derived.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {e}")
            self.status("Failed to load private key.")

    def load_public_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files","*.pem"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            key = load_public_key_from_pem(data)
            self.public_key = key
            self.status(f"Loaded public key from {path}")
            messagebox.showinfo("Success", "Public key loaded.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load public key: {e}")
            self.status("Failed to load public key.")

    # ------------------- Signing -------------------
    def select_file_to_sign(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self.file_to_sign = path
        messagebox.showinfo("File selected", f"File to sign: {os.path.basename(path)}")

    def sign_action(self):
        if not self.private_key:
            messagebox.showwarning("No private key", "Load or generate a private key before signing.")
            return
        # determine input: file or text
        data_bytes = None
        if self.file_to_sign:
            try:
                with open(self.file_to_sign, "rb") as f:
                    data_bytes = f.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")
                return
        else:
            txt = self.sign_text.get("1.0", tk.END).encode('utf-8')
            if not txt.strip():
                messagebox.showwarning("No input", "Enter text or select a file to sign.")
                return
            data_bytes = txt

        hash_algo = self._get_hash_algo()
        try:
            sig = sign_bytes(self.private_key, data_bytes, hash_algo=hash_algo)
            sig_b64 = base64.b64encode(sig).decode('utf-8')
            self.signature_box.delete("1.0", tk.END)
            self.signature_box.insert(tk.END, sig_b64)
            self.last_signature_bytes = sig
            self.status("Data signed successfully.")
            messagebox.showinfo("Signed", "Successfully created signature (shown in base64).")
        except Exception as e:
            messagebox.showerror("Signing error", f"Could not sign: {e}")
            self.status("Signing failed.")

    def copy_signature(self):
        sig = self.signature_box.get("1.0", tk.END).strip()
        if not sig:
            messagebox.showwarning("No signature", "No signature to copy.")
            return
        pyperclip.copy(sig)
        self.status("Signature copied to clipboard.")

    def save_signature(self):
        sig = self.signature_box.get("1.0", tk.END).strip()
        if not sig:
            messagebox.showwarning("No signature", "No signature to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".sig", filetypes=[("Signature files","*.sig"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(sig)
            self.status(f"Signature saved to {path}")
            messagebox.showinfo("Saved", f"Signature saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save signature: {e}")

    def clear_sign_inputs(self):
        self.sign_text.delete("1.0", tk.END)
        self.signature_box.delete("1.0", tk.END)
        self.file_to_sign = None
        self.last_signature_bytes = None
        self.status("Sign inputs cleared.")

    # ------------------- Verification -------------------
    def select_file_to_verify(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self.file_to_verify = path
        messagebox.showinfo("File selected", f"File to verify: {os.path.basename(path)}")

    def paste_signature(self):
        try:
            text = pyperclip.paste()
            self.verify_sig_entry.delete(0, tk.END)
            self.verify_sig_entry.insert(0, text)
            self.status("Pasted signature from clipboard.")
        except Exception:
            messagebox.showwarning("Clipboard", "Could not read clipboard.")

    def verify_action(self):
        if not self.public_key:
            messagebox.showwarning("No public key", "Load a public key (or private key) before verifying.")
            return

        # get signature
        sig_b64 = self.verify_sig_entry.get().strip()
        if not sig_b64:
            messagebox.showwarning("No signature", "Enter or paste a base64 signature to verify.")
            return
        try:
            sig_bytes = base64.b64decode(sig_b64)
        except Exception:
            messagebox.showerror("Bad signature", "Signature is not valid base64.")
            return

        # get data
        if self.file_to_verify:
            try:
                with open(self.file_to_verify, "rb") as f:
                    data_bytes = f.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")
                return
        else:
            data_bytes = self.verify_text.get("1.0", tk.END).encode('utf-8')
            if not data_bytes.strip():
                messagebox.showwarning("No input", "Enter text or select a file to verify.")
                return

        hash_algo = self._get_hash_algo()
        try:
            verify_bytes(self.public_key, sig_bytes, data_bytes, hash_algo=hash_algo)
            self.verify_result_label.config(text="Result: ✅ Signature is VALID", fg="green")
            self.status("Signature verified: VALID.")
            messagebox.showinfo("Verified", "Signature is VALID for provided input.")
        except InvalidSignature:
            self.verify_result_label.config(text="Result: ❌ Signature is INVALID", fg="red")
            self.status("Signature verification failed: INVALID.")
            messagebox.showwarning("Invalid", "Signature did NOT verify for provided input.")
        except Exception as e:
            self.verify_result_label.config(text="Result: ❌ Error during verification", fg="red")
            self.status(f"Verification error: {e}")
            messagebox.showerror("Error", f"Error during verification: {e}")

    def clear_verify_inputs(self):
        self.verify_text.delete("1.0", tk.END)
        self.verify_sig_entry.delete(0, tk.END)
        self.file_to_verify = None
        self.verify_result_label.config(text="Result: -", fg="black")
        self.status("Verify inputs cleared.")

    # ------------------- Utilities -------------------
    def _get_hash_algo(self):
        name = self.hash_var.get()
        if name == "SHA384":
            return hashes.SHA384()
        if name == "SHA512":
            return hashes.SHA512()
        return hashes.SHA256()

    def status(self, text: str):
        self.status_text.config(text=text)

# --------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = RSASignTool(root)
    root.mainloop()
