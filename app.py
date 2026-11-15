
from flask import Flask, request, jsonify, send_from_directory
from urllib.parse import urlsplit
import ipaddress
import re
import psutil
import datetime
import platform

app = Flask(__name__)


# ==================================
# HOME PAGE
# ==================================

@app.route("/")
def home():
    return send_from_directory(".", "webpage.html")
@app.route("/monitor")
def monitor():
    return send_from_directory(".", "monitor.html")
# ==================================
# URL DETECTOR
# ==================================

@app.route("/api/scan", methods=["POST"])
def scan_url():

    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Invalid scheme")

        hostname = parsed.hostname

        if not hostname or not parsed.netloc:
            raise ValueError("Missing hostname")

        if parsed.port is not None:
            if not 1 <= parsed.port <= 65535:
                raise ValueError("Invalid port")

    except ValueError:
        return jsonify({
            "error": "Please enter a valid HTTP or HTTPS URL."
        }), 400

    reasons = []
    host = hostname.lower().rstrip(".")

    try:
        ipaddress.ip_address(host)
        reasons.append("The hostname is an IP address.")
    except ValueError:
        pass

    if parsed.username is not None or parsed.password is not None:
        reasons.append("The URL contains embedded login information.")

    if "xn--" in host:
        reasons.append("The hostname contains a punycode label.")

    if len(url) > 200:
        reasons.append("The URL is unusually long.")

    if re.search(
        r"login|verify|secure|account|password|wallet",
        url,
        re.IGNORECASE
    ):
        reasons.append("The URL contains a potentially sensitive keyword.")

    if reasons:
        result = "suspicious"
        message = (
            "Suspicious indicators found. "
            "Investigate this URL before opening it."
        )
    else:
        result = "no_obvious_warning"
        message = (
            "No warning was detected by the basic rules. "
            "This does not guarantee that the URL is safe."
        )

    return jsonify({
        "url": url,
        "result": result,
        "message": message,
        "reasons": reasons
    })


# ==================================
# LOCAL LAPTOP MONITORING
# ==================================

@app.route("/api/system-monitor")
def system_monitor():

    # CPU usage
    cpu = psutil.cpu_percent(interval=1)

    # RAM usage
    ram = psutil.virtual_memory().percent

    # Laptop startup time
    boot_time = datetime.datetime.fromtimestamp(
        psutil.boot_time()
    )

    # Calculate laptop uptime
    uptime = str(
        datetime.datetime.now() - boot_time
    ).split(".")[0]

    # Running processes
    processes = []

    for process in psutil.process_iter(['pid', 'name']):

        try:
            processes.append({
                "pid": process.info['pid'],
                "name": process.info['name']
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return jsonify({

        "cpu": cpu,

        "ram": ram,

        "uptime": uptime,

        "boot_time": boot_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "os": platform.system(),

        "processes": processes[:20]

    })


# ==================================
# RUN FLASK APPLICATION
# ==================================

if __name__ == "__main__":
    app.run(debug=True)
