"""
SpaceSec Shield · Phase 5 — Monitoring Dashboard (backend)
==========================================================
Receives packet-decision events from the Satellite Node (Phase 3 logic) and
serves aggregated state to the browser.

Run on the Ground Station (or a separate monitor VM):
    pip3 install flask
    python3 dashboard.py
Then open http://<this-vm-ip>:5000  (e.g. http://192.168.10.10:5000)

Endpoints
    POST /api/event   <- Satellite posts one JSON event here (per packet)
    GET  /api/state   -> browser polls this every second
    POST /api/reset   -> clear all state for a clean demo run
    GET  /            -> the live dashboard page
"""

from flask import Flask, request, jsonify, render_template
from collections import deque
import time

app = Flask(__name__)

# --- In-memory state (no database needed for the demo) --------------------
events = deque(maxlen=500)        # recent security events (for the feed)

# Cumulative counters so the chart line keeps rising for the whole demo,
# independent of the deque's max length.
totals = {"accepted": 0, "rejected": 0}
latency_sum = {"ms": 0, "n": 0}   # running average of accepted-packet latency

VALID_SEVERITIES = {"LOW", "MEDIUM", "CRITICAL"}

# Map a rejection reason to a severity, used only if the Satellite did not
# send one (the Satellite normally sets it — see Sub-Task 4).
REASON_SEVERITY = {
    "OK":           "LOW",
    "TAG_FAIL":     "CRITICAL",
    "REPLAY_TS":    "CRITICAL",
    "DUP_NONCE":    "CRITICAL",
    "DECRYPT_FAIL": "CRITICAL",
    "BAD_FORMAT":   "MEDIUM",
}


@app.route("/api/event", methods=["POST"])
def ingest_event():
    """Satellite Node posts one packet-decision event here."""
    e = request.get_json(force=True, silent=True) or {}

    # Fill in defaults defensively.
    e.setdefault("timestamp", int(time.time() * 1000))
    e.setdefault("type", "REJECTED")
    e.setdefault("reason", "OK")
    if e.get("severity") not in VALID_SEVERITIES:
        e["severity"] = REASON_SEVERITY.get(e.get("reason", ""), "LOW")

    # Update cumulative counters.
    if e["type"] == "ACCEPTED":
        totals["accepted"] += 1
        lat = e.get("latency_ms")
        if isinstance(lat, (int, float)) and lat >= 0:
            latency_sum["ms"] += lat
            latency_sum["n"] += 1
    else:
        totals["rejected"] += 1

    events.append(e)
    return jsonify({"status": "stored"}), 200


@app.route("/api/state")
def state():
    """Browser polls this every second."""
    recent = list(events)[-30:]

    # Link status: derived from the most recent activity, not lifetime totals.
    if not events:
        link = "DISCONNECTED"
    else:
        window = list(events)[-10:]
        rej = sum(1 for e in window if e.get("type") == "REJECTED")
        acc = sum(1 for e in window if e.get("type") == "ACCEPTED")
        link = "DEGRADED" if rej and rej >= acc else "CONNECTED"

    avg_latency = round(latency_sum["ms"] / latency_sum["n"]) if latency_sum["n"] else 0

    return jsonify({
        "link_status": link,
        "accepted": totals["accepted"],
        "rejected": totals["rejected"],
        "avg_latency_ms": avg_latency,
        "recent": recent,            # newest-last; the page reverses for display
    })


@app.route("/api/reset", methods=["POST"])
def reset():
    """Clear all state so each live demo starts from zero."""
    events.clear()
    totals["accepted"] = 0
    totals["rejected"] = 0
    latency_sum["ms"] = 0
    latency_sum["n"] = 0
    return jsonify({"status": "reset"}), 200


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    # host=0.0.0.0 so the Satellite VM can POST to this machine over space-net.
    app.run(host="0.0.0.0", port=5000, debug=True)
