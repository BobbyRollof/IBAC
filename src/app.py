from flask import Flask, request, jsonify
import subprocess
import tempfile
import json
import os

app = Flask(__name__)
POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy.rego")
QUERY = "data.example.allow"

def evaluate_with_opa(input_obj):
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
        json.dump(input_obj, tf)
        tf.flush()
        input_path = tf.name

    try:
        cmd = ["opa", "eval", "-i", input_path, "-d", POLICY_FILE, "-f", "json", QUERY]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return {"error": proc.stderr.strip() or "OPA returned non-zero exit"}, 500

        # OPA json format: {"result":[{"expressions":[{"value": <value>, ...}]}]}
        out = json.loads(proc.stdout)
        value = None
        try:
            value = out["result"][0]["expressions"][0]["value"]
        except Exception:
            return {"error": "unexpected opa output", "raw": out}, 500

        return {"allow": value, "raw": out}, 200
    finally:
        try:
            os.remove(input_path)
        except Exception:
            pass

@app.route("/v1/decision", methods=["POST"])
def decision():
    if not request.is_json:
        return jsonify({"error": "expected application/json"}), 400
    input_obj = request.get_json()
    result, status = evaluate_with_opa(input_obj)
    return jsonify(result), status

if __name__ == "__main__":
    app.run(port=5000)
