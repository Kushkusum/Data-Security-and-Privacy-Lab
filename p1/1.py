import hashlib
import time
import threading
from cryptography.fernet import Fernet

# -----------------------
# Confidentiality
# -----------------------
def confidentiality_demo():
    print("\n--- Confidentiality Demo ---")
    # Generate a secret key for encryption
    key = Fernet.generate_key()
    cipher = Fernet(key)

    message = "Top Secret: AI is amazing!"
    print("Original Message:", message)

    # Encrypt
    encrypted = cipher.encrypt(message.encode())
    print("Encrypted Message:", encrypted)

    # Decrypt
    decrypted = cipher.decrypt(encrypted).decode()
    print("Decrypted Message:", decrypted)

# -----------------------
# Integrity
# -----------------------
def integrity_demo():
    print("\n--- Integrity Demo ---")
    message = "Data must stay the same"
    # Calculate hash
    hash1 = hashlib.sha256(message.encode()).hexdigest()
    print("Original Hash:", hash1)

    # Simulate tampering
    tampered_message = "Data must stay different"
    hash2 = hashlib.sha256(tampered_message.encode()).hexdigest()

    print("Tampered Hash :", hash2)
    if hash1 == hash2:
        print("✅ Integrity OK")
    else:
        print("❌ Integrity Breach! Data has been altered")

# -----------------------
# Availability
# -----------------------
def availability_demo():
    print("\n--- Availability Demo ---")
    data_store = {"file1": "important data", "file2": "student records"}

    def server():
        while True:
            print("✅ Server running. Files available:", list(data_store.keys()))
            time.sleep(2)

    def ddos_attack():
        print("⚠️ Simulating DDoS Attack... server busy!")
        time.sleep(5)
        print("⚠️ Server unresponsive for some time!")
        time.sleep(3)
        print("✅ Server restored and available again.")

    # Run server in background
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()

    # Simulate attack after some time
    time.sleep(3)
    ddos_attack()

# -----------------------
# Run all demos
# -----------------------
if __name__ == "__main__":
    confidentiality_demo()
    integrity_demo()
    availability_demo()
