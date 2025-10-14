# 🔒 Security Policy

## Encrypted Notes App — Version 1.0

The Encrypted Notes App is designed with **user privacy and data security** as its top priority.  
All stored notes and account data are **fully encrypted locally** using industry-standard cryptography.

---

## Security Overview
- **End-to-End Encryption:**  
  Notes are encrypted and decrypted locally on the user’s device using **Fernet (AES-128/CBC + HMAC)** from the Python `cryptography` library.
- **Password-Based Key Derivation:**  
  Each password generates a unique cryptographic key using **PBKDF2** with a per-user salt.
- **No Remote Storage:**  
  The app performs all encryption, decryption, and file storage locally — **no data ever leaves your system**.
- **Secure Account Handling:**  
  Passwords are never stored in plain text. Only salted hashes are kept in the local `users.json` file.
- **Account Deletion:**  
  Users can permanently delete all their encrypted data from the device.

---

## 🚨 Reporting a Vulnerability
If you discover a potential security issue, please report it responsibly.

1. **Do not** post details publicly in issue trackers or forums.  
2. Send a detailed report including:
   - Steps to reproduce the issue
   - Expected vs. actual behavior
   - Any relevant logs or error messages (if safe to share)
3. Email your report to:  
   📧 **anonymous-hide-me-pls@proton.me**  

We will acknowledge your report within **24/48 hours** and work to address it as quickly as possible.

---

## 🔐 Security Best Practices for Users
To maintain your privacy and data safety:
- Use a **strong, unique password** for your account.
- **Do not share your password** or encryption key files.
- Keep your **local files and backups secure**.
- Always close the app when not in use, especially on shared devices.
- Update to the latest release for bug fixes and security patches.

---

## Known Limitations (v1.0)
- Data is stored locally; losing access to your password means notes cannot be recovered.
- No network encryption layer is required (local-only app).
- Physical access to your machine could expose encrypted files, though they remain unreadable without your key.

---

## Version History
- **1.0.0 – Initial Release**
  - Core encryption and authentication system
  - Local encrypted file storage
  - Secure password change and deletion features
  - UI theming and autosave options

---

## Acknowledgements
This project uses the **cryptography** Python library and follows **OWASP** recommendations for password-based encryption and local data protection.

---

