# Android Native Function Hooking Report

## 🎯 Objective

The goal of this challenge was to hook into the native function `getSecretMessage` within the APK `Apk_task1`, dynamically analyze it using Frida, and extract the hidden flag processed by the app’s native code.

---

## 🛠️ Tools & Environment

- Android Emulator with root access
- Frida (client + frida-server)
- ADB (Android Debug Bridge)
- Objection (optional)
- APK decompiler (JADX) [used for reconnaissance]

---

## 🔍 Process Overview

### Step 1: Initial Setup
```bash
# Install APK to device
adb install Apk_task1.apk

# Push and start Frida server on the device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
Step 2: Locate the Target Process

# Confirm the app is running
frida-ps -U | grep apk_task1
Step 3: Identify Native Library
Upon inspection (via JADX and runtime checks), the app uses a native library:
✅ libnative-lib.so
Target function of interest: getSecretMessage

🧬 Step 4: Hooking the Function
Created a Frida script to dynamically intercept the native function.


// hook_getSecret.js
Java.perform(function () {
    console.log("[*] Java runtime loaded");

    var lib = Process.findModuleByName("libnative-lib.so");
    if (lib) {
        console.log("[+] Loaded native library: " + lib.name);

        var addr = Module.findExportByName("libnative-lib.so", "getSecretMessage");
        if (addr) {
            console.log("[+] Hooking address: " + addr);

            Interceptor.attach(addr, {
                onLeave: function (retval) {
                    var result = retval.readCString();
                    console.log("[*] Intercepted result: " + result);

                    if (result.indexOf("Holberton{") !== -1) {
                        console.log("[!!] FLAG FOUND: " + result);
                    }
                }
            });
        }
    }
});
Step 5: Run the Script

frida -U -f com.example.apk_task1 -l hook_getSecret.js --no-pause
Once the app executed the native function, Frida intercepted the result and printed it to the terminal.

✅ Result


[!!] FLAG FOUND: Holberton{native_hooking_is_no_different_at_all}
🔎 Analysis Summary
The function getSecretMessage was compiled into native code and not accessible via standard Java method hooking.

Frida's Interceptor.attach() was used to capture its return value.

The flag was stored in memory and returned by the native function — no UI interaction was needed.

Runtime manipulation allowed access to otherwise hidden data.

🧪 Key Commands Recap

adb install Apk_task1.apk
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
frida -U -f com.example.apk_task1 -l hook_getSecret.js --no-pause
🧾 Conclusion
Successfully leveraged Frida to intercept and analyze native code execution in a live Android application. This demonstrates the power of dynamic analysis in uncovering hidden flags and bypassing static code limitations. The technique is especially useful for black-box testing when source code is unavailable.