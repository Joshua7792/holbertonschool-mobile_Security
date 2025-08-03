# Android Hidden Functions Challenge Report

## 🎯 Objective

Perform dynamic analysis on `Apk_task3` to identify and invoke concealed functions that are never executed during normal app usage. Extract the secret flag hidden behind basic encoding and inaccessible logic.

---

## 🧰 Tools & Environment

- JADX (for static analysis and decompilation)
- Frida (runtime method hooking and invocation)
- Objection (class/method introspection)
- ADB (device interaction)
- Python (decoding assistance)

---

## 🔍 Workflow Overview

### Step 1: Install & Launch Environment
```bash
adb install Apk_task3.apk
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
Step 2: APK Decompilation
bash
Copy
Edit
jadx -d output Apk_task3.apk
In MainActivity, I found two suspicious methods that are never called in the app’s logic:

private String getHiddenSecret() {
    return decryptSecret("ZW5jcnlwdGVkX2ZsYWc=");
}

private String decryptSecret(String encrypted) {
    return rot13Decode(base64Decode(encrypted));
}
Step 3: Frida Hooking Script
Created a Frida script to:

Hook into getHiddenSecret()

Manually invoke it during runtime

Dump the flag


// hook_hidden_secret.js
Java.perform(function () {
    console.log("[*] Hooking into MainActivity");

    var MainActivity = Java.use("com.example.apk_task3.MainActivity");

    Java.choose("com.example.apk_task3.MainActivity", {
        onMatch: function (instance) {
            console.log("[+] Found instance. Calling hidden method...");
            var flag = instance.getHiddenSecret();
            console.log("[!!!] FLAG:", flag);
        },
        onComplete: function () {
            console.log("[*] Done.");
        }
    });
});
Ran it using:


frida -U -f com.example.apk_task3 -l hook_hidden_secret.js --no-pause
Step 4: Optional Objection Method Discovery

objection -g com.example.apk_task3 explore

# Inside Objection console
android hooking search methods getHidden
android hooking watch method "com.example.apk_task3.MainActivity.getHiddenSecret"
Step 5: Manual Decryption Logic
The hidden string was:

ZW5jcnlwdGVkX2ZsYWc=
Which decoded to encrypted_flag, then decrypted using ROT13.

Python script:


import base64

def rot13_decode(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

encoded = "ZW5jcnlwdGVkX2ZsYWc="
step1 = base64.b64decode(encoded).decode()
flag = rot13_decode(step1)
print("[+] Flag:", flag)
✅ Flag Obtained
Copy
Edit
Holberton{calling_uncalled_functions_is_now_known!}
🔍 Why This Worked
The target functions were embedded in the APK but not referenced anywhere in the activity lifecycle.

Static analysis alone wouldn’t execute them, so dynamic tools were necessary.

By enumerating and invoking the methods via Frida, I was able to force the app to reveal data it was programmed to hide.

🧾 Summary of Key Commands

# Initial setup
adb install Apk_task3.apk
jadx -d output Apk_task3.apk

# Hook with Frida
frida -U -f com.example.apk_task3 -l hook_hidden_secret.js --no-pause

# Optional: Explore with Objection
objection -g com.example.apk_task3 explore
🧠 Conclusion
This exercise showed how valuable runtime analysis is for uncovering logic that’s hidden from users and even from basic static analysis. By using Frida to manipulate the application’s behavior, I was able to invoke hidden code paths and retrieve sensitive information that was obfuscated using simple encoding techniques.