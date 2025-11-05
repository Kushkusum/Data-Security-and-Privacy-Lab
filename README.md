# Data Security and Privacy Lab

Collection of short, hands-on lab programs for learning data security, privacy and related tools.  
Each subfolder contains one or more small programs. These are educational examples.

Run them from the command line:

```bash
cd <folder-name>
python <script>.py         # or
streamlit run <script>.py  # for Streamlit apps

```
## Folder summary

1. Exploring CIA Triad
Simulations and demonstration scripts for Confidentiality, Integrity, and Availability.

2. Dictionary Attack (educational / defensive)
Examples for plaintext/hash checks, safe brute-force simulations (demo only), password-strength checking, and export reporting.

3. Virus Simulation (safe & educational)
Non-malicious simulations of malware behaviour for defender training and detection exercises.

4. Vulnerability Analyzer
Static heuristics scanner that inspects source files for common insecure patterns and bad coding practices.

5. Phishing Website Detection
Dataset + a simple scikit-learn classifier to distinguish phishing vs legitimate URLs (features: URL length, @, https, suspicious words, etc.).

6. Secure Messaging (TLS + E2EE)
Prototype and sequence diagrams demonstrating transport security and end-to-end encryption (server acts as relay only).

7. Hash Functions & Obfuscation
Hashing utilities (SHA-256, MD5) and safe obfuscation demos (encodings, simple rename-obfuscator).

8. Digital Signatures, Authentication & Authorization
RSA signature generation/verification, JWT-based authentication/authorization examples, and small web/CLI demos for protected APIs.

9. PII Classification & Anonymization
Detect PII in structured/unstructured data; apply k-anonymity, l-diversity, t-closeness; and a small differential-privacy demo
