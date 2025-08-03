# Android Cryptography Challenge Report

## 🎯 Objective

Analyze and decrypt network traffic from `Apk_task2` by intercepting encrypted HTTP responses and reversing the cryptographic logic within the app to retrieve the hidden flag.

---

## 🧰 Tools Used

- Burp Suite (for HTTP interception and certificate installation)
- JADX (APK decompilation)
- ADB (device interaction)
- Python (AES decryption)

---

## 🔧 Step-by-Step Analysis

### Step 1: Install and Configure
```bash
# Install the target APK
adb install Apk_task2.apk

# Redirect emulator/device traffic through Burp proxy
adb shell settings put global http_proxy 192.168.1.100:8080
Launched Burp Suite and configured it to listen on port 8080.

Installed Burp’s CA certificate on the device to intercept HTTPS traffic.

Step 2: Capture Encrypted Traffic
Once the app was running, Burp Suite captured this encrypted JSON response:

{
  "encrypted_data": "U2FsdGVkX1+vupppZksvRf5...",
  "iv": "1234567890123456"
}
Step 3: Reverse Engineering
Decompiled the APK using JADX to search for hardcoded keys and cryptographic logic:

jadx -d output Apk_task2.apk
Identified two key files:

// KeyManager.java
private static final String KEY = "MySecretKey12345";

// CryptoUtils.java
public static String decrypt(String data, String key) {
    // AES decryption logic with CBC mode
}
The AES key and IV were hardcoded.

The function used AES/CBC/PKCS5Padding — a common but exploitable pattern if keys are not protected.

Step 4: Decrypt the Response
Built a simple Python script to replicate the decryption process locally.

# decrypt_flag.py
import base64
from Crypto.Cipher import AES

encrypted = "U2FsdGVkX1+vupppZksvRf5..."  # Intercepted from Burp
key = "MySecretKey12345"                   # Found in APK
iv = "1234567890123456"                    # Found in JSON or code

cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
decrypted = cipher.decrypt(base64.b64decode(encrypted))
flag = decrypted.decode('utf-8').rstrip('\0')
print("[+] Decrypted Flag:", flag)
✅ Result
Holberton{keystore_is_not_as_safe_as_u_think!}
🔍 What Made This Work
The app used symmetric AES encryption but failed to secure its key and IV.

Both values were embedded in the APK and easily extracted.

No key derivation or secure storage (like Android Keystore) was used.

This made all encrypted responses fully reversible.

🔐 Security Implication
Embedding cryptographic keys directly in app code poses a major security risk. Any attacker with access to the APK can decrypt all communications if encryption is not implemented securely.

💻 Recap of Key Commands
adb install Apk_task2.apk
jadx -d output Apk_task2.apk
python3 decrypt_flag.py
🧾 Conclusion
This challenge clearly demonstrates the risks of insecure cryptographic implementations in mobile apps. By combining network interception with static code analysis, I was able to retrieve the flag with no interaction from the app itself. Always protect sensitive keys using secure APIs like the Android Keystore and avoid static embedding.
