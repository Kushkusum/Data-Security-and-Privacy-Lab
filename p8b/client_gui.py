import tkinter as tk
from tkinter import messagebox
import requests

API_URL = "http://127.0.0.1:5000"
token = None  # store JWT here

def register_user():
    u, p = entry_user.get(), entry_pass.get()
    if not u or not p:
        messagebox.showerror("Error", "Enter username & password")
        return
    r = requests.post(f"{API_URL}/register", json={"username": u, "password": p})
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, r.text)

def login_user():
    global token
    u, p = entry_user.get(), entry_pass.get()
    r = requests.post(f"{API_URL}/login", json={"username": u, "password": p})
    data = r.json()
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, str(data))
    if "access_token" in data:
        token = data["access_token"]

def get_profile():
    if not token:
        messagebox.showerror("Error", "Login first!")
        return
    r = requests.get(f"{API_URL}/profile", headers={"Authorization": f"Bearer {token}"})
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, r.text)

def get_admin():
    if not token:
        messagebox.showerror("Error", "Login first!")
        return
    r = requests.get(f"{API_URL}/admin", headers={"Authorization": f"Bearer {token}"})
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, r.text)

# --- GUI setup ---
root = tk.Tk()
root.title("JWT Auth Client")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack()

tk.Label(frame, text="Username:").grid(row=0, column=0)
entry_user = tk.Entry(frame, width=20)
entry_user.grid(row=0, column=1)

tk.Label(frame, text="Password:").grid(row=1, column=0)
entry_pass = tk.Entry(frame, width=20, show="*")
entry_pass.grid(row=1, column=1)

tk.Button(frame, text="Register", command=register_user, bg="lightblue").grid(row=2, column=0, pady=5)
tk.Button(frame, text="Login", command=login_user, bg="lightgreen").grid(row=2, column=1, pady=5)
tk.Button(frame, text="Profile", command=get_profile, bg="orange").grid(row=3, column=0, pady=5)
tk.Button(frame, text="Admin", command=get_admin, bg="red").grid(row=3, column=1, pady=5)

text_output = tk.Text(frame, height=10, width=50)
text_output.grid(row=4, column=0, columnspan=2, pady=10)

root.mainloop()
