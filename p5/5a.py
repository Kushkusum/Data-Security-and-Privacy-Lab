import tkinter as tk
from tkinter import messagebox
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

# --------------------------
# Load dataset
dataset_file = "C:/Users/HP/Desktop/dsp/URL_dataset[1].csv"

df = pd.read_csv(dataset_file, encoding='ISO-8859-1', on_bad_lines='skip')

# Map labels: legitimate -> 0, phishing -> 1
df['Label'] = df['type'].map({'legitimate': 0, 'phishing': 1})

# --------------------------
# Feature extraction function
def extract_features(url):
    features = []
    features.append(len(url))                  # URL length
    features.append(1 if '@' in url else 0)    # '@' symbol
    features.append(1 if url.startswith('https') else 0)  # 'https'
    features.append(url.count('-'))            # number of '-'
    features.append(url.count('.'))            # number of '.'
    suspicious_words = ['login', 'verify', 'secure', 'update', 'account']
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)  # suspicious words
    return features

# Apply feature extraction
X = df['url'].astype(str).apply(lambda x: extract_features(x)).tolist()
y = df['Label']

# --------------------------
# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
print("Model Accuracy (on test set):", accuracy_score(y_test, y_pred))

# --------------------------
# GUI Application
class PhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Website Detector")
        self.root.geometry("450x250")
        
        tk.Label(root, text="Enter URL to Check:", font=("Arial", 14)).pack(pady=10)
        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack(pady=5)
        
        tk.Button(root, text="Check URL", font=("Arial", 12), command=self.check_url).pack(pady=15)
        
        self.result_label = tk.Label(root, text="", font=("Arial", 12))
        self.result_label.pack(pady=10)
    
    def check_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return
        
        features = extract_features(url)
        prediction = model.predict([features])[0]
        
        if prediction == 1:
            self.result_label.config(text="⚠️ Warning: Phishing Website Detected!", fg="red")
        else:
            self.result_label.config(text="✅ Safe: Legitimate Website", fg="green")

# --------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()
