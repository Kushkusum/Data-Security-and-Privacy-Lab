import socket, ssl, threading, time, base64, hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext

HOST = "127.0.0.1"
PORT = 12345

# --- derive Fernet key from passphrase ---
def derive_key(passphrase):
    return base64.urlsafe_b64encode(hashlib.sha256(passphrase.encode()).digest())

class ChatClientPanel:
    def __init__(self, parent, name, passphrase, side, color):
        self.name = name
        self.color = color
        self.cipher = Fernet(derive_key(passphrase))

        # Frame for this client
        frame = tk.Frame(parent, bd=3, relief="ridge")
        frame.pack(side=side, fill="both", expand=True, padx=5, pady=5)

        # Title
        tk.Label(frame, text=f"Client: {name}", font=("Arial", 12, "bold")).pack(pady=5)

        # Chat box
        self.chat_area = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, state="disabled", width=50, height=20, bg="#1e1e1e", fg="white"
        )
        self.chat_area.pack(padx=5, pady=5)

        # Add tags for colored messages
        self.chat_area.tag_config("Alice", foreground="lime")
        self.chat_area.tag_config("Bob", foreground="cyan")
        self.chat_area.tag_config("system", foreground="white")

        # Typing status
        self.typing_label = tk.Label(frame, text="", fg="orange")
        self.typing_label.pack()

        # Entry + Send
        entry_frame = tk.Frame(frame)
        entry_frame.pack(pady=5)

        self.entry = tk.Entry(entry_frame, width=40)
        self.entry.pack(side=tk.LEFT, padx=5)
        self.entry.bind("<KeyRelease>", self.send_typing_status)

        send_btn = tk.Button(entry_frame, text="Send", command=self.send_message)
        send_btn.pack(side=tk.LEFT)

        # Setup TLS socket
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((HOST, PORT))
        self.ssock = context.wrap_socket(sock, server_hostname=HOST)

        self.add_message("[🔒] Connected via TLS. E2EE enabled.", "system")

        # Start receiver thread
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def add_message(self, msg, sender="system", self_sent=False):
        self.chat_area.config(state="normal")
        if self_sent:
            # Sender sees only their own text (no name prefix)
            self.chat_area.insert(tk.END, msg + "\n", self.name)
        else:
            # Show with name if coming from the other person
            if sender in ["Alice", "Bob"]:
                self.chat_area.insert(tk.END, msg + "\n", sender)
            else:
                self.chat_area.insert(tk.END, msg + "\n", "system")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state="disabled")

    def receive_messages(self):
        while True:
            try:
                data = self.ssock.recv(4096)
                if not data:
                    break
                msg = self.cipher.decrypt(data).decode()
                if msg.startswith("[") and msg.endswith("is typing...]"):
                    self.typing_label.config(text=msg)
                    self.chat_area.after(2000, lambda: self.typing_label.config(text=""))
                else:
                    # Example msg: "[12:00:00] Alice: Hi"
                    if "Alice:" in msg:
                        self.add_message(msg, "Alice")
                    elif "Bob:" in msg:
                        self.add_message(msg, "Bob")
                    else:
                        self.add_message(msg, "system")
            except:
                break

    def send_typing_status(self, event=None):
        status_msg = f"[{self.name} is typing...]"
        encrypted = self.cipher.encrypt(status_msg.encode())
        self.ssock.sendall(encrypted)

    def send_message(self):
        msg = self.entry.get().strip()
        if msg:
            timestamp = time.strftime("%H:%M:%S")
            full_msg = f"[{timestamp}] {self.name}: {msg}"

            # Show only msg locally (no prefix)
            self.add_message(msg, self.name, self_sent=True)

            # Send encrypted full msg (with name so others know sender)
            encrypted = self.cipher.encrypt(full_msg.encode())
            self.ssock.sendall(encrypted)

            self.entry.delete(0, tk.END)

# --- Main app ---
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Secure Chat Demo (TLS + E2EE)")

    passphrase = "secretpass"

    # Two clients side by side
    ChatClientPanel(root, "Alice", passphrase, tk.LEFT, "lime")
    ChatClientPanel(root, "Bob", passphrase, tk.RIGHT, "cyan")

    root.mainloop()
