"""Tiny Flask app with deliberate command injection for smoke-testing codeql-auto.

DO NOT DEPLOY. The vulnerabilities are intentional.
"""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "")
    # BUG: shell=True + untrusted input -> command injection (CWE-78)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # BUG: same class, different sink
    return subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)


if __name__ == "__main__":
    app.run()
