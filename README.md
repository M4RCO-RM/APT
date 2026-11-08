# APK Permission Patcher

Upload an APK → scans AndroidManifest.xml for missing permissions → injects them → re-signs → returns patched APK.

**Required permissions checked (16 total):**
- INTERNET, ACCESS_NETWORK_STATE, WAKE_LOCK, POST_NOTIFICATIONS
- CAMERA, READ_MEDIA_IMAGES, READ_MEDIA_VIDEO, RECORD_AUDIO
- ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION
- READ_CONTACTS, READ_SMS, READ_CALL_LOG, READ_PHONE_STATE
- RECEIVE_BOOT_COMPLETED, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS

## Stack
- **Backend:** Flask + apktool 2.11.1 + uber-apk-signer 1.3.0
- **Signing:** v1 + v2 + v3 signatures via debug keystore
- **Frontend:** Vanilla JS, no framework

## Run locally

```bash
# 1. Install Java 21
# 2. Run build script (downloads jars)
bash build.sh

# 3. Start server
python app.py
# → http://localhost:7331
```

## Deploy on Render

See deploy guide below or just connect the GitHub repo — `render.yaml` handles everything.

---
